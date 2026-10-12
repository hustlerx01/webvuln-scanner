"""Fallback for OpenSSL < 3.4 (no -not_after): sign an already-expired leaf with the lab CA using `cryptography`."""
import datetime as dt, pathlib, ipaddress
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
D = pathlib.Path(__file__).resolve().parent / "certs"
ca_key = serialization.load_pem_private_key((D / "ca.key").read_bytes(), None)
ca = x509.load_pem_x509_certificate((D / "ca.pem").read_bytes())
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime(2025, 1, 1)).not_valid_after(dt.datetime(2025, 2, 1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .sign(ca_key, hashes.SHA256()))
(D / "exp.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
(D / "exp.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
print("expired cert via cryptography fallback")
