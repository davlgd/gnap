#!/usr/bin/env python3
"""Generate crates/gnap-registry/src/generated.rs from registries/*.csv.

Two shapes, depending on what the registry holds:

  - a *value* registry (a value travels inside a message) becomes a Rust enum
    with an `Unregistered(String)` variant. GNAP is extensible: an unknown
    value is not a parse error, it is an unregistered value, and the caller
    decides what to do with it (RFC 9635 Appendix D).

  - a *field-name* registry becomes a slice of &str, used to check that an
    extension field is registered.

Usage: python3 tools/generate_registry.py (requires rustfmt on PATH)
"""
import csv
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSV_DIR = ROOT / "registries"
OUT = ROOT / "crates" / "gnap-registry" / "src" / "generated.rs"

# file stem -> (Rust type name, doc line)
VALUE_REGISTRIES = {
    "gnap-access-token-flags": ("AccessTokenFlag", "Flags carried by an access token (RFC 9635 §2.1.1, §3.2.1)."),
    "gnap-assertion-formats": ("AssertionFormat", "Assertion formats (RFC 9635 §3.4.1)."),
    "gnap-error-codes": ("ErrorCode", "Client-facing error codes (RFC 9635 §3.6)."),
    "gnap-interaction-finish-methods": ("InteractionFinishMethod", "Interaction finish methods (RFC 9635 §2.5.2)."),
    "gnap-interaction-start-modes": ("InteractionStartMode", "Interaction start modes (RFC 9635 §2.5.1)."),
    "gnap-key-formats": ("KeyFormat", "Public key formats (RFC 9635 §7.1)."),
    "gnap-key-proofing-methods": ("KeyProofingMethod", "Key proofing methods (RFC 9635 §7.3)."),
    "gnap-rs-facing-error-codes": ("RsErrorCode", "Error codes for the RS-facing API (RFC 9767 §3.5)."),
    "gnap-token-formats": ("TokenFormat", "Access token formats (RFC 9767 §2.2)."),
}

FIELD_REGISTRIES = {
    "gnap-authorization-server-discovery-fields": ("AS_DISCOVERY_FIELDS", "RFC 9635 §9"),
    "gnap-client-instance-display-fields": ("CLIENT_DISPLAY_FIELDS", "RFC 9635 §2.3.2"),
    "gnap-client-instance-fields": ("CLIENT_INSTANCE_FIELDS", "RFC 9635 §2.3"),
    "gnap-grant-request-parameters": ("GRANT_REQUEST_PARAMETERS", "RFC 9635 §2"),
    "gnap-grant-response-parameters": ("GRANT_RESPONSE_PARAMETERS", "RFC 9635 §3"),
    "gnap-interaction-hints": ("INTERACTION_HINTS", "RFC 9635 §2.5.3"),
    "gnap-interaction-mode-responses": ("INTERACTION_MODE_RESPONSES", "RFC 9635 §3.3"),
    "gnap-subject-information-request-fields": ("SUBJECT_REQUEST_FIELDS", "RFC 9635 §2.2"),
    "gnap-subject-information-response-fields": ("SUBJECT_RESPONSE_FIELDS", "RFC 9635 §3.4"),
    "gnap-resource-set-registration-request-parameters": ("RESOURCE_SET_REQUEST_PARAMETERS", "RFC 9767 §3.4"),
    "gnap-resource-set-registration-response-parameters": ("RESOURCE_SET_RESPONSE_PARAMETERS", "RFC 9767 §3.4"),
    "gnap-rs-facing-discovery-document-fields": ("RS_DISCOVERY_FIELDS", "RFC 9767 §3.1"),
    "gnap-token-introspection-request": ("INTROSPECTION_REQUEST_FIELDS", "RFC 9767 §3.3"),
    "gnap-token-introspection-response": ("INTROSPECTION_RESPONSE_FIELDS", "RFC 9767 §3.3"),
}


def entries(stem):
    """First column of every row, deduplicated while preserving order.

    Some registries list the same value twice (`httpsig` appears as both
    `string` and `object`).
    """
    rows = list(csv.reader((CSV_DIR / f"{stem}.csv").read_text(encoding="utf-8").splitlines()))
    seen, out = set(), []
    for row in rows[1:]:
        if not row or not row[0].strip():
            continue
        v = row[0].strip()
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def variant(value):
    """`user_code_uri` -> `UserCodeUri`, `cert#S256` -> `CertS256`."""
    parts = re.split(r"[-_#\s]+", value)
    return "".join(p[:1].upper() + p[1:] for p in parts if p)


def render_enum(type_name, doc, values):
    L = [f"/// {doc}", "///",
         "/// Generated from the IANA registry. A value that is not registered is",
         "/// carried by [`Unregistered`](Self::Unregistered): GNAP is designed to be",
         "/// extended, so an unknown value is not a parse error (RFC 9635 Appendix D).",
         "#[derive(Debug, Clone, PartialEq, Eq, Hash)]",
         f"pub enum {type_name} {{"]
    for v in values:
        L.append(f"    /// `{v}`")
        L.append(f"    {variant(v)},")
    L.append("    /// A value absent from the IANA registry when this file was generated.")
    L.append("    Unregistered(String),")
    L.append("}")
    L.append("")
    L.append(f"impl {type_name} {{")
    L.append("    /// Every registered value, in registry order.")
    L.append(f"    pub const REGISTERED: &'static [&'static str] = &[")
    for v in values:
        L.append(f'        "{v}",')
    L.append("    ];")
    L.append("")
    L.append("    /// The on-the-wire representation.")
    L.append("    #[must_use]")
    L.append("    pub fn as_str(&self) -> &str {")
    L.append("        match self {")
    for v in values:
        L.append(f'            Self::{variant(v)} => "{v}",')
    L.append("            Self::Unregistered(s) => s.as_str(),")
    L.append("        }")
    L.append("    }")
    L.append("")
    L.append("    /// Returns `false` when the value is absent from the IANA registry.")
    L.append("    #[must_use]")
    L.append("    pub const fn is_registered(&self) -> bool {")
    L.append("        !matches!(self, Self::Unregistered(_))")
    L.append("    }")
    L.append("}")
    L.append("")
    L.append(f"impl From<&str> for {type_name} {{")
    L.append("    fn from(s: &str) -> Self {")
    L.append("        match s {")
    for v in values:
        L.append(f'            "{v}" => Self::{variant(v)},')
    L.append("            other => Self::Unregistered(other.to_owned()),")
    L.append("        }")
    L.append("    }")
    L.append("}")
    L.append("")
    L.append(f"crate::impl_registry_traits!({type_name});")
    return "\n".join(L)


def main():
    L = ["// @generated by tools/generate_registry.py — DO NOT EDIT.",
         "// Source: registries/*.csv, vendored from IANA.",
         "// Regenerate: python3 tools/fetch_registries.py && python3 tools/generate_registry.py",
         ""]

    for stem, (type_name, doc) in VALUE_REGISTRIES.items():
        L.append(render_enum(type_name, doc, entries(stem)))
        L.append("")

    L.append("// --- field-name registries -------------------------------------------")
    L.append("// Used to check whether an extension field is registered (Appendix D).")
    L.append("")
    for stem, (const_name, ref) in FIELD_REGISTRIES.items():
        vals = entries(stem)
        L.append(f"/// Registered fields — {ref}.")
        L.append(f"pub const {const_name}: &[&str] = &[")
        for v in vals:
            L.append(f'    "{v}",')
        L.append("];")
        L.append("")

    # Format before replacing the artifact: a missing or failing formatter must
    # not leave a partially regenerated file behind.
    formatted = subprocess.run(
        ["rustfmt", "--edition", "2021", "--emit", "stdout"],
        input="\n".join(L) + "\n", text=True, capture_output=True, check=True,
    ).stdout
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(formatted, encoding="utf-8")

    n_enum = sum(len(entries(s)) for s in VALUE_REGISTRIES)
    n_field = sum(len(entries(s)) for s in FIELD_REGISTRIES)
    print(f"{len(VALUE_REGISTRIES)} enums ({n_enum} values) + "
          f"{len(FIELD_REGISTRIES)} field tables ({n_field} names)")
    print(f"Wrote: {OUT}")


if __name__ == "__main__":
    main()
