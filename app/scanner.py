import ssl
import socket
import tempfile
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import algorithms_list as algos

def get_cert_signature_algo(cert_der):
    """Extract signature algorithm from certificate using OpenSSL."""
    with tempfile.NamedTemporaryFile(delete=True) as tmp:
        tmp.write(cert_der)
        tmp.flush()
        out = subprocess.check_output([
            "openssl", "x509", "-inform", "DER", "-in", tmp.name, "-text", "-noout"
        ], text=True)

    for line in out.splitlines():
        line = line.strip().lower()
        if line.startswith("signature algorithm:"):
            return line.replace("signature algorithm:", "").strip()
    return None

def get_cert_signature_algo_oid(cert_der):
    # """Extract signature algorithm from certificate using OpenSSL."""
    # with tempfile.NamedTemporaryFile(delete=True) as tmp:
    #     tmp.write(cert_der)
    #     tmp.flush()
    #     out = subprocess.check_output([
    #         "openssl", "x509", "-inform", "DER", "-in", tmp.name, "-text", "-noout"
    #     ], text=True)

    # for line in out.splitlines():
    #     line = line.strip().lower()
    #     if line.startswith("signature algorithm:"):
    #         return line.replace("signature algorithm:", "").strip()
    # return None
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    # Return the signature algorithm as an OID string
    return cert.signature_algorithm_oid.dotted_string

def get_kem(hostname):
    """Ask OpenSSL which KEM was negotiated (OpenSSL ≥ 3.2)."""
    try:
        out = subprocess.check_output(
            ["openssl", "s_client", "-connect", f"{hostname}:443", "-tls1_3", "-brief"],
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
    # """Ask OpenSSL which KEM was negotiated (OpenSSL ≥ 3.2)."""
    # try:
    #     out = subprocess.check_output(
    #         ["openssl", "s_client", "-connect", f"{hostname}:443", "-tls1_3", "-brief"],
    #         stderr=subprocess.STDOUT,
    #         text=True
    #     )
    # except subprocess.CalledProcessError:
    #     return None

    # for line in out.splitlines():
    #     line = line.strip()
    #     if line.lower().startswith("key exchange:"):
    #         return line.split(":", 1)[1].strip()
    # return None
    """Ask OpenSSL which KEM was negotiated (OpenSSL ≥ 3.2)."""
    try:
        out = subprocess.check_output(
            ["openssl", "s_client", "-connect", f"{hostname}:443", "-tls1_3", "-brief"],
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
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, 443)) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            
            tls_version = ssock.version()
            cipher = ssock.cipher()[0]

            print(f"Connected to {hostname}")
            print("TLS version:", tls_version)
            print("Cipher:", cipher)
            # print("Peer cert:", ssock.getpeercert())

            cert_der = ssock.getpeercert(binary_form=True)

            print(f"TLS version:      {tls_version}")
            print(f"Cipher:           {cipher}")

            # Check certificate signature algorithm
            sig_algo_oid = get_cert_signature_algo_oid(cert_der)
            sig_algo=get_cert_signature_algo(cert_der)
            print(f"Cert signature:   {sig_algo}")

            # Check key exchange via OpenSSL
            kem_oid = get_kem_oid(hostname)
            kem=get_kem(hostname)
            print(f"Key exchange:     {kem}")

            # === PQ Checks ===
            pq_tls = tls_version == "TLSv1.3"
            pq_kem = kem in algos.PQS_KEMS if kem else False
            pq_sig = any(alg in (sig_algo or "") for alg in algos.PQS_SIGNATURES)

            print("\n=== Evaluation ===")
            print(f"TLS 1.3:                          {'YES' if pq_tls else 'NO'}")
            print(f"Post-quantum key exchange:        {'YES' if pq_kem else 'NO'}")
            print(f"Post-quantum cert signature:      {'YES' if pq_sig else 'NO'}")

            if pq_tls and pq_kem and pq_sig:
                print("\nFINAL RESULT:  **FULLY POST-QUANTUM SAFE**")
            else:
                print("\nFINAL RESULT:  **NOT FULLY POST-QUANTUM SAFE**")
                if not pq_kem:
                    print(" - Key exchange is NOT post-quantum.")
                if not pq_sig:
                    print(" - Certificate signature is NOT post-quantum.")
                if not pq_tls:
                    print(" - TLS version is not 1.3.")

            # Afisare certificat in format openssl (optional)
            # print("\n=== OpenSSL Certificate Dump ===\n")
            # cert_der = ssock.getpeercert(binary_form=True)

            # # Write certificate to temporary file
            # with tempfile.NamedTemporaryFile(delete=True) as tmp:
            #     tmp.write(cert_der)
            #     tmp.flush()

            #     # Call OpenSSL to print certificate in readable form
            #     result = subprocess.run(
            #         ["openssl", "x509", "-inform", "DER", "-in", tmp.name, "-text", "-noout"],
            #         capture_output=True,
            #         text=True
            #     )

            #     print(result.stdout)
            #     if result.stderr:
            #         print("OpenSSL error:", result.stderr)

if __name__ == "__main__":
    scan_tls("google.com")
