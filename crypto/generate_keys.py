"""
generate_keys.py
----------------
Generates an ECDSA (SECP256R1 / P-256) key pair for a trusted image source.

In the real system, each trusted source (application upload pipeline,
verified partner API, trusted CMS) has its own key pair. The PRIVATE key
stays strictly on the source and is used to sign images. The PUBLIC key is
distributed to the gateway so it can verify signatures without ever being
able to forge new ones (non-repudiation).
"""

import argparse
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def generate_key_pair(out_dir: str, name: str) -> tuple[str, str]:
    """Generates ECDSA P-256 key pair and saves them to out_dir."""
    os.makedirs(out_dir, exist_ok=True)

    # SECP256R1 (P-256) is a standard NIST curve: ~128-bit security,
    # ultra-fast hardware-accelerated signature verification suitable for real-time gateway routing.
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    private_path = os.path.join(out_dir, f"{name}_private.pem")
    public_path = os.path.join(out_dir, f"{name}_public.pem")

    with open(private_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(public_path, "wb") as f:
        f.write(
            public_key.bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ) if hasattr(public_key, 'bytes') else public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    try:
        os.chmod(private_path, 0o600)
    except Exception:
        pass

    return private_path, public_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate an ECDSA key pair for a trusted image source.")
    parser.add_argument("--out-dir", default="keys", help="Directory to write key files into.")
    parser.add_argument("--name", default="trusted-source-1", help="Identifier for this source.")
    args = parser.parse_args()

    priv, pub = generate_key_pair(args.out_dir, args.name)
    print(f"[+] Private key (keep on the SOURCE only): {priv}")
    print(f"[+] Public key  (distribute to GATEWAY):   {pub}")
