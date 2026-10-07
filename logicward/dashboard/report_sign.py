"""Detached Ed25519 signatures for the PDF forensic report (Prompt 3.2).

Keys come from LOGICWARD_REPORT_KEY (a PEM private key path). In demo mode a
keypair is generated under logicward/data/keys/ on first use (gitignored).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from logicward import config

KEY_DIR = config.DATA_DIR / "keys"
PRIV_PATH = KEY_DIR / "report_ed25519.pem"
PUB_PATH = KEY_DIR / "report_ed25519.pub.pem"


def _fingerprint(pub_pem: bytes) -> str:
    return "sha256:" + hashlib.sha256(pub_pem).hexdigest()[:32]


def load_or_create_key() -> Ed25519PrivateKey:
    env_path = os.environ.get("LOGICWARD_REPORT_KEY")
    if env_path:
        return serialization.load_pem_private_key(Path(env_path).read_bytes(), password=None)
    if PRIV_PATH.exists():
        return serialization.load_pem_private_key(PRIV_PATH.read_bytes(), password=None)
    # demo mode: generate + persist a keypair
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    PRIV_PATH.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    PUB_PATH.write_bytes(public_pem(key))
    return key


def public_pem(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def sign_pdf(pdf: bytes) -> dict:
    """Return a detached-signature manifest for `pdf` bytes."""
    key = load_or_create_key()
    pub = public_pem(key)
    digest = hashlib.sha256(pdf).hexdigest()
    sig = key.sign(pdf).hex()
    return {"algo": "ed25519", "sha256": digest, "signature": sig,
            "public_key_pem": pub.decode("ascii"), "fingerprint": _fingerprint(pub)}


def verify_report(pdf: bytes, sig_manifest: dict, pub_pem: bytes | None = None) -> bool:
    """Verify a PDF against its detached signature. `pub_pem` overrides the key in
    the manifest (e.g. an independently distributed public key)."""
    try:
        pem = pub_pem or sig_manifest["public_key_pem"].encode("ascii")
        pub = serialization.load_pem_public_key(pem)
        if not isinstance(pub, Ed25519PublicKey):
            return False
        if hashlib.sha256(pdf).hexdigest() != sig_manifest.get("sha256"):
            return False
        pub.verify(bytes.fromhex(sig_manifest["signature"]), pdf)
        return True
    except Exception:  # noqa: BLE001
        return False


def sig_json(manifest: dict) -> bytes:
    return json.dumps(manifest, indent=2).encode("utf-8")
