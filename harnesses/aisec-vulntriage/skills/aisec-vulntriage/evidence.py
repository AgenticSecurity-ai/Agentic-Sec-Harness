#!/usr/bin/env python3
# Copyright (C) 2026 Isao Takaesu
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Append-only, hash-chained, signed evidence log (VAT) for aisec-vulntriage.

DESIGN.md §3.5: every triage verdict is recorded as *which inputs (digested) →
what priority → what rationale*, chained with SHA-256 and signed. This is the
auditable "who decided what, on what basis" trail. A reader can verify the chain
end-to-end (tamper-evident) and, when a signing key is configured, verify each
entry's signature.

Stdlib only for the chain. The signature is PLUGGABLE (v1 walking skeleton; the
signing-key management is an open design decision — DESIGN.md §10):

  * ECDSA P-256  — used when the `cryptography` package is importable AND
    VULNTRIAGE_EVIDENCE_EC_KEY points to a PEM EC private key. This is the mode
    DESIGN §3.5 targets (asymmetric → third-party verifiable). Roadmap: keyless
    signing + a Sigstore Rekor transparency log (DESIGN §8).
  * HMAC-SHA256  — stdlib fallback when VULNTRIAGE_EVIDENCE_KEY (a shared secret)
    is set but ECDSA is unavailable. Tamper-evident to anyone holding the key;
    NOT third-party verifiable. Labelled honestly as such in `sig_alg`.
  * none         — chain-only when no key is configured. The hash chain still
    makes the log tamper-EVIDENT (any edit breaks the chain); it is just not
    signed. A one-time warning is emitted.

The log is JSON Lines (one entry per line, append-only) at state/evidence.log.
Each entry:
  {seq, ts, record, prev_hash, entry_hash, sig, sig_alg}
where entry_hash = SHA-256(seq \\n ts \\n prev_hash \\n canonical(record)).
"""
import os
import sys
import hmac
import json
import hashlib
from datetime import datetime, timezone

GENESIS_HASH = "0" * 64  # prev_hash of the first entry

# Env knobs (non-secret path / secret material live outside the repo per B2).
_EC_KEY_ENV = "VULNTRIAGE_EVIDENCE_EC_KEY"   # path to a PEM EC private key (ECDSA)
_HMAC_KEY_ENV = "VULNTRIAGE_EVIDENCE_KEY"    # shared secret (HMAC fallback)

_warned_unsigned = False


def _canonical(obj):
    """Deterministic JSON encoding so the same record always hashes identically."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def digest(text):
    """SHA-256 hex of a UTF-8 string — used to record inputs by digest, not raw."""
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _load_ec_signer():
    """Return (sign_fn, alg_label) for ECDSA P-256 if available+configured, else None.
    sign_fn(entry_hash_hex:str) -> signature hex."""
    key_path = os.environ.get(_EC_KEY_ENV, "").strip()
    if not key_path:
        return None
    try:
        from cryptography.hazmat.primitives import hashes, serialization  # noqa: F401
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError:
        return None
    try:
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    except (OSError, ValueError) as e:
        raise RuntimeError(f"cannot load EC signing key {key_path}: {e}")
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise RuntimeError(f"{key_path} is not an EC private key (need ECDSA P-256)")

    def _sign(entry_hash_hex):
        sig = key.sign(entry_hash_hex.encode("ascii"), ec.ECDSA(hashes.SHA256()))
        return sig.hex()

    return _sign, "ECDSA-P256-SHA256"


def _load_signer():
    """Resolve the active signer: ECDSA if possible, else HMAC, else none."""
    global _warned_unsigned
    ec_signer = _load_ec_signer()
    if ec_signer:
        return ec_signer
    secret = os.environ.get(_HMAC_KEY_ENV, "").strip()
    if secret:
        def _sign(entry_hash_hex, _key=secret.encode("utf-8")):
            return hmac.new(_key, entry_hash_hex.encode("ascii"),
                            hashlib.sha256).hexdigest()
        return _sign, "HMAC-SHA256"
    if not _warned_unsigned:
        print("[warn] evidence log is UNSIGNED (chain-only): set "
              f"{_EC_KEY_ENV} (ECDSA, preferred) or {_HMAC_KEY_ENV} (HMAC) to sign. "
              "The hash chain still makes tampering evident.", file=sys.stderr,
              flush=True)
        _warned_unsigned = True
    return (lambda _h: ""), "none"


class EvidenceLog:
    """Append-only hash-chained evidence log over a JSONL file."""

    def __init__(self, path):
        self.path = path
        self._sign, self._alg = _load_signer()

    def _last(self):
        """Return (last_seq, last_entry_hash) or (-1, GENESIS_HASH) if empty."""
        if not os.path.exists(self.path):
            return -1, GENESIS_HASH
        last = None
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last = line
        if not last:
            return -1, GENESIS_HASH
        obj = json.loads(last)
        return int(obj["seq"]), obj["entry_hash"]

    def append(self, record):
        """Append one record; returns the written entry dict (with seq/hash/sig)."""
        seq, prev_hash = self._last()
        seq += 1
        ts = _now_iso()
        entry_hash = hashlib.sha256(
            f"{seq}\n{ts}\n{prev_hash}\n{_canonical(record)}".encode("utf-8")
        ).hexdigest()
        entry = {
            "seq": seq,
            "ts": ts,
            "record": record,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
            "sig": self._sign(entry_hash),
            "sig_alg": self._alg,
        }
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        # Append-only: never rewrite prior lines. Flush + fsync so a crash mid-run
        # cannot lose a committed verdict (the log is the audit record).
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(_canonical(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return entry

    def head(self):
        """Return (seq, entry_hash) of the current chain head for a digest reference."""
        return self._last()


def verify(path):
    """Re-walk the log and check the hash chain (and HMAC sigs when the key is set).
    Returns (ok:bool, checked:int, error:str|None). ECDSA sigs need the public key
    to verify and are treated as structurally-present-only here (chain is authoritative
    for tamper-evidence). Intended for tests / an audit command."""
    if not os.path.exists(path):
        return True, 0, None
    prev_hash = GENESIS_HASH
    expect_seq = 0
    hmac_secret = os.environ.get(_HMAC_KEY_ENV, "").strip().encode("utf-8")
    checked = 0
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if obj["seq"] != expect_seq:
                return False, checked, f"seq gap at line {lineno}"
            if obj["prev_hash"] != prev_hash:
                return False, checked, f"chain break at seq {obj['seq']}"
            want = hashlib.sha256(
                f"{obj['seq']}\n{obj['ts']}\n{obj['prev_hash']}\n"
                f"{_canonical(obj['record'])}".encode("utf-8")
            ).hexdigest()
            if want != obj["entry_hash"]:
                return False, checked, f"entry_hash mismatch at seq {obj['seq']}"
            if obj.get("sig_alg") == "HMAC-SHA256" and hmac_secret:
                want_sig = hmac.new(hmac_secret, obj["entry_hash"].encode("ascii"),
                                    hashlib.sha256).hexdigest()
                if not hmac.compare_digest(want_sig, obj.get("sig", "")):
                    return False, checked, f"HMAC mismatch at seq {obj['seq']}"
            prev_hash = obj["entry_hash"]
            expect_seq += 1
            checked += 1
    return True, checked, None


if __name__ == "__main__":
    # Small CLI: `evidence.py verify <path>` for audits / tests.
    import argparse
    ap = argparse.ArgumentParser(description="Verify an evidence-log hash chain")
    ap.add_argument("cmd", choices=["verify"])
    ap.add_argument("path")
    a = ap.parse_args()
    ok, n, err = verify(a.path)
    print(f"ok={ok} checked={n}" + (f" error={err}" if err else ""))
    sys.exit(0 if ok else 1)
