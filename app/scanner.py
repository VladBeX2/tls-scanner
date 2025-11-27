import ssl
import socket

def scan_tls(hostname):
	ctx = ssl.create_default_context()
	with socket.create_connection((hostname, 443)) as sock:
		with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
			print(f"Connected to {hostname}")
			print("TLS version:", ssock.version())
			print("Cipher:", ssock.cipher())
			print("Peer cert:", ssock.getpeercert())

if __name__ == "__main__":
	scan_tls("google.com")
