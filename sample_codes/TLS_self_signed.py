import os

import OpenSSL.crypto


def generate_self_signed_certificate(
    key_file, cert_file, key_size=2048, valid_days=365
):
    # Generate a new private key
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, key_size)

    # Create a self-signed certificate
    cert = OpenSSL.crypto.X509()
    cert.get_subject().CN = "rasoul.edu"  # Common Name (replace with your domain name)
    cert.set_serial_number(int.from_bytes(os.urandom(16), "big"))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(valid_days * 24 * 60 * 60)  # Validity period in seconds
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    # Save the private key and certificate to files
    with open(key_file, "wb") as f:
        f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))

    with open(cert_file, "wb") as f:
        f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))


if __name__ == "__main__":
    key_file = "self_signed_private_key.pem"
    cert_file = "self_signed_cert.pem"

    generate_self_signed_certificate(key_file, cert_file)

    print(
        f"Self-signed certificate and private key have been generated: {cert_file}, {key_file}"
    )
