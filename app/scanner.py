import ssl
import socket
import tempfile
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import algorithms_list as algos
import platform, os
import sys
import ipaddress
from urllib.parse import urlparse
OPENSSL_EXE_PATH = r".\OpenSSL-Win64\bin\openssl.exe"

if platform.system() == "Windows":
    if os.path.exists(OPENSSL_EXE_PATH):
        OPENSSL_RUN_CMD = OPENSSL_EXE_PATH
    else:
        print(f"ATENTIE: Nu am gasit OpenSSL la calea: {OPENSSL_EXE_PATH}")
        OPENSSL_RUN_CMD = "openssl"
else:
    OPENSSL_RUN_CMD = "openssl"

def get_cert_signature_algo(cert_der):
    """Extract signature algorithm from certificate using OpenSSL."""
    with tempfile.NamedTemporaryFile(delete=True) as tmp:
        tmp.write(cert_der)
        tmp.flush()
        out = subprocess.check_output([
            OPENSSL_RUN_CMD, "x509", "-inform", "DER", "-in", tmp.name, "-text", "-noout"
        ], text=True)

    for line in out.splitlines():
        line = line.strip().lower()
        if line.startswith("signature algorithm:"):
            return line.replace("signature algorithm:", "").strip()
    return None

def get_cert_signature_algo_oid(cert_der):
    # """Extract signature algorithm from certificate using OpenSSL."""
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    return cert.signature_algorithm_oid.dotted_string

def get_kem(hostname):
    """Ask OpenSSL which KEM was negotiated (OpenSSL ≥ 3.2)."""
    try:
        out = subprocess.check_output(
            [OPENSSL_RUN_CMD, "s_client", "-connect", f"{hostname}:443", "-tls1_3", "-brief"],
            stderr=subprocess.STDOUT,
            text=True
        )
    except subprocess.CalledProcessError:
        return None

    for line in out.splitlines():
        line = line.strip()
        if line.lower().startswith("key exchange:"):
            return line.split(":", 1)[1].strip()
    return None

def get_kem_oid(hostname):
    """Ask OpenSSL which KEM was negotiated (OpenSSL ≥ 3.2)."""
    try:
        out = subprocess.check_output(
            [OPENSSL_RUN_CMD, "s_client", "-connect", f"{hostname}:443", "-tls1_3", "-brief"],
            stderr=subprocess.STDOUT,
            text=True
        )
    except subprocess.CalledProcessError:
        return None

    for line in out.splitlines():
        line = line.strip()
        if line.lower().startswith("key exchange:"):
            return line.split(":", 1)[1].strip()
    return None

def scan_tls(hostname):
    vulnerabilities = []
    
    ctx = ssl.create_default_context()
    
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                
                tls_version = ssock.version()
                cipher = ssock.cipher()[0]
                cert_der = ssock.getpeercert(binary_form=True)

                sig_algo_oid = get_cert_signature_algo_oid(cert_der)
                kem_name = get_kem(hostname) 

                is_pq_tls = (tls_version == "TLSv1.3")
                
                is_pq_kem = False
                if kem_name:
                    is_pq_kem = any(k in kem_name for k in ["Kyber", "ML-KEM"]) 

                is_pq_sig = False
                if sig_algo_oid:
                    is_pq_sig = sig_algo_oid in algos.PQS_SIGNATURES

                if not is_pq_tls:
                    vulnerabilities.append({
                        "name": f"Versiune TLS Veche ({tls_version})",
                        "severity": "High",
                        "details": f"Serverul a negociat {tls_version}. Doar TLS 1.3 este considerat sigur pentru migrarea PQC.",
                        "suggestion": "Actualizați configurația serverului pentru a forța TLS 1.3."
                    })

                if not is_pq_kem:
                    kem_display = kem_name if kem_name else "Necunoscut/Clasic"
                    vulnerabilities.append({
                        "name": f"Schimb de Chei Clasic ({kem_display})",
                        "severity": "High",
                        "details": f"Mecanismul de schimb de chei '{kem_display}' este vulnerabil la atacul 'Store Now, Decrypt Later'.",
                        "suggestion": "Compilați OpenSSL cu oqs-provider și activați algoritmi hibrizi (ex: X25519_Kyber768)."
                    })

                if not is_pq_sig:
                    vulnerabilities.append({
                        "name": "Semnătură Certificat Clasică (RSA/ECDSA)",
                        "severity": "Medium", 
                        "details": f"Certificatul este semnat folosind un algoritm clasic (OID: {sig_algo_oid}).",
                        "suggestion": "Pe termen lung, migrați la o autoritate de certificare care oferă certificate semnate cu Dilithium sau Falcon."
                    })

    except socket.gaierror:
        vulnerabilities.append({
            "name": "Eroare Conexiune",
            "severity": "Critical",
            "details": f"Nu s-a putut găsi host-ul: {hostname}",
            "suggestion": "Verificați dacă ați introdus corect adresa IP sau domeniul."
        })
    except socket.timeout:
        vulnerabilities.append({
            "name": "Timeout",
            "severity": "Critical",
            "details": f"Serverul {hostname} nu a răspuns în 5 secunde.",
            "suggestion": "Verificați conexiunea la internet sau setările firewall."
        })
    except Exception as e:
        vulnerabilities.append({
            "name": "Eroare Internă Scanare",
            "severity": "Critical",
            "details": str(e),
            "suggestion": "Verificați dacă OpenSSL este instalat și adăugat în PATH."
        })

    return vulnerabilities

def check_input(value: str):
    try:
        ipaddress.ip_address(value)
        return True," "
    except ValueError:
        pass

    parsed = urlparse(value)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return True," "

    return False, "Format invalid. Introduceți o adresă IP sau un URL valid."

if __name__ == "__main__":
    input_url=""
    if len(sys.argv) > 1:
        input_url = sys.argv[1]
    else:
        input_url = print("Introduceți adresa IP sau domeniul de scanat")
        exit(0)

    k,m=check_input(input_url)
    if not k:
        print(m)
        exit(0)

    print(f"Scanning {input_url}...")
    v=scan_tls(input_url)
    print(v)
