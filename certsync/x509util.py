from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

_PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----\s*",
    re.DOTALL,
)


@dataclass(slots=True)
class CertificateMeta:
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    sha256: str
    san_dns_names: list[str]



def read_text(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8")



def split_cert_chain(pem_text: str) -> list[str]:
    matches = _PEM_CERT_RE.findall(pem_text)
    if not matches:
        raise ValueError("No PEM certificate block found")
    return [m.strip() + "\n" for m in matches]



def extract_leaf_certificate(pem_text: str) -> str:
    return split_cert_chain(pem_text)[0]



def strip_ec_parameters(private_key_pem: str) -> str:
    lines = private_key_pem.splitlines()
    out: list[str] = []
    skip = False
    for line in lines:
        if line.startswith("-----BEGIN EC PARAMETERS-----"):
            skip = True
            continue
        if line.startswith("-----END EC PARAMETERS-----"):
            skip = False
            continue
        if not skip:
            out.append(line)
    text = "\n".join(out).strip()
    return text + "\n"



def parse_certificate_meta(pem_text: str) -> CertificateMeta:
    cert = x509.load_pem_x509_certificate(extract_leaf_certificate(pem_text).encode("utf-8"))
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns_names = list(san.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        san_dns_names = []

    not_before = cert.not_valid_before_utc.astimezone(timezone.utc)
    not_after = cert.not_valid_after_utc.astimezone(timezone.utc)

    return CertificateMeta(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial_number=hex(cert.serial_number),
        not_before=not_before,
        not_after=not_after,
        sha256=hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
        san_dns_names=san_dns_names,
    )
