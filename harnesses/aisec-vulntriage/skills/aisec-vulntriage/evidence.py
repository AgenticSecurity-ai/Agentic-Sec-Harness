#!/usr/bin/env python3
# Copyright (C) 2026 Isao Takaesu
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Append-only, hash-chained, signed evidence log (VAT) for aisec-vulntriage.

DESIGN.md §3.5: every triage verdict is recorded as *which inputs (digested) →
what priority → what rationale*, chained with SHA-256 and signed. This is the
auditable "who decided what, on what basis" trail. A reader can verify the chain
end-to-end (tamper-evident) and, when a signing key is configured, verify each
entry's signature.

Stdlib only for the chain. The signature is a DECIDED pluggable scheme resolved in
priority order (DESIGN.md §3.5 / §10 / §15) — `sig_alg` on every entry names the tier
honestly so a downgrade is always visible to an auditor:

  * ECDSA P-256 (KMS)  — off-host signing (DESIGN §15, sub-milestone S3.5.1). Used when
    VULNTRIAGE_EVIDENCE_KMS_KEY_ID names an AWS KMS asymmetric key (ECC_NIST_P256,
    SIGN_VERIFY). The private key NEVER leaves the HSM and every Sign is CloudTrail-
    logged off-host, so this closes the local-PEM limit below (host compromise no longer
    yields the private key). Signing shells out to `aws kms sign` (external CLI, like the
    Prowler/Trivy collectors) so the harness stays stdlib-only. `sig_alg` =
    "ECDSA-P256-SHA256-KMS". Verification is AWS-INDEPENDENT: export the public key once
    (`aws kms get-public-key`) to VULNTRIAGE_EVIDENCE_EC_PUBKEY and verify() checks sigs
    offline. Tried FIRST when configured.
  * ECDSA P-256 (PEM)  — used when the `cryptography` package is importable AND
    VULNTRIAGE_EVIDENCE_EC_KEY points to a PEM EC private key. Asymmetric →
    third-party verifiable; the audit-grade local mode DESIGN §3.5 targets.
  * HMAC-SHA256  — stdlib fallback when VULNTRIAGE_EVIDENCE_KEY (a shared secret)
    is set but ECDSA is unavailable. Tamper-evident to a holder of the secret, but
    the verifier IS the forger (symmetric) → integrity-only, NOT non-repudiation.
    Labelled honestly as such in `sig_alg`; never dressed up as ECDSA.
  * none         — chain-only when no key is configured (the DEFAULT). The hash
    chain still makes the log tamper-EVIDENT (any edit breaks the chain); it is
    just not signed. A one-time warning is emitted.

Both ECDSA tiers sign the SAME input (the hex entry_hash string) and emit a DER
signature, so a mixed log (some entries PEM-signed, some KMS-signed after a cutover)
verifies end-to-end via one code path per curve; each entry self-describes its `sig_alg`.

Key management: the local ECDSA key (VULNTRIAGE_EVIDENCE_EC_KEY) is a PEM on the host,
kept with the host's other secrets (never in the repo, convention #3). Known limit — a
local key means host compromise ⇒ signature forgery: an attacker holding the key can
rewrite and re-sign the log, so local-PEM signing is NOT non-repudiation against a
host-level breach. The KMS tier (DESIGN §15) closes this: the key is unstealable and
signing is off-host-logged (residual gap vs Sigstore keyless + Rekor — an operator can
still sign forgeries while holding the scoped credential — stated honestly; Sigstore is
deferred to S3.5b). The KMS credential MUST be separate from the read-only scan role
(only kms:Sign + kms:GetPublicKey on the one key ARN); the scan role stays pure read-only.

Fail-CLOSED: if a signer is CONFIGURED and signing fails (e.g. no AWS reach for KMS), the
signer RAISES rather than silently writing sig_alg=none — a false "unsigned" downgrade
would corrupt the audit record. run.py signs every verdict into the log BEFORE posting or
marking, so a raise aborts the run before any Discord post / ledger mark (no double-post;
findings stay unmarked and retry next run).

The log is JSON Lines (one entry per line, append-only) at state/evidence.log.
Each entry:
  {seq, ts, record, prev_hash, entry_hash, sig, sig_alg}
where entry_hash = SHA-256(seq \\n ts \\n prev_hash \\n canonical(record)).
"""
import os
import sys
import hmac
import json
import time
import base64
import shutil
import hashlib
import tempfile
import subprocess
from datetime import datetime, timezone

GENESIS_HASH = "0" * 64  # prev_hash of the first entry

# Env knobs (non-secret path / secret material live outside the repo per B2).
_EC_KEY_ENV = "VULNTRIAGE_EVIDENCE_EC_KEY"       # path to a PEM EC private key (local ECDSA)
_HMAC_KEY_ENV = "VULNTRIAGE_EVIDENCE_KEY"        # shared secret (HMAC fallback)
_KMS_KEY_ENV = "VULNTRIAGE_EVIDENCE_KMS_KEY_ID"  # AWS KMS asymmetric key id/ARN (non-secret)
_KMS_PROFILE_ENV = "VULNTRIAGE_EVIDENCE_KMS_PROFILE"  # AWS profile scoped to kms:Sign (separate from scan role)
_KMS_REGION_ENV = "VULNTRIAGE_EVIDENCE_KMS_REGION"    # optional region override (else parsed from a key ARN)
_EC_PUBKEY_ENV = "VULNTRIAGE_EVIDENCE_EC_PUBKEY"      # path to public-key PEM for offline ECDSA verify (KMS or local)
_AWS_BIN_ENV = "AWS_BIN"                          # override the `aws` CLI path (default: PATH lookup)

_ECDSA_ALG_LABEL = "ECDSA-P256-SHA256"           # local PEM tier
_KMS_ALG_LABEL = "ECDSA-P256-SHA256-KMS"         # off-host KMS tier
_KMS_SIGN_ALG = "ECDSA_SHA_256"                  # KMS SigningAlgorithm (matches P-256 + SHA-256)
_KMS_SIGN_RETRIES = 3                            # bounded retry on transient KMS failures, then fail-closed

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

    return _sign, _ECDSA_ALG_LABEL


def _region_from_arn(key_id):
    """Extract the region from a KMS key ARN (arn:aws:kms:<region>:...); "" for a
    bare key-id or alias (the CLI then uses the profile/ambient region)."""
    parts = key_id.split(":")
    if len(parts) >= 4 and parts[0] == "arn" and parts[2] == "kms":
        return parts[3]
    return ""


def _kms_permanent(msg):
    """True if a KMS/CLI error is non-transient (retrying won't help) → raise now."""
    m = msg or ""
    return any(tok in m for tok in (
        "AccessDenied", "NotFoundException", "ValidationException",
        "InvalidKeyUsage", "DisabledException", "InvalidGrantToken",
        "ExpiredToken", "UnrecognizedClientException", "InvalidClientTokenId",
        "could not be found", "Unable to locate credentials"))


def _kms_sign(base_cmd, entry_hash_hex):
    """Shell out to `aws kms sign` over the RAW ascii bytes of entry_hash_hex — the
    SAME input the local PEM signer feeds ec.ECDSA(SHA256) — and return the DER
    signature as hex. FAIL-CLOSED: bounded retry on transient errors, then raise;
    never returns an empty/unsigned value (that would be a false audit downgrade)."""
    msg = entry_hash_hex.encode("ascii")
    # fileb:// passes raw bytes regardless of the CLI's cli_binary_format (v1/v2-safe).
    fd, msg_path = tempfile.mkstemp(prefix="vt-kms-", suffix=".bin")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(msg)
        cmd = base_cmd + ["--message", "fileb://" + msg_path]
        last_err = ""
        for attempt in range(1, _KMS_SIGN_RETRIES + 1):
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            except (OSError, subprocess.TimeoutExpired) as e:
                last_err = str(e)
            else:
                if proc.returncode == 0:
                    b64 = (proc.stdout or "").strip()
                    if not b64:
                        raise RuntimeError("aws kms sign returned an empty Signature")
                    try:
                        return base64.b64decode(b64, validate=True).hex()
                    except ValueError as e:  # binascii.Error ⊂ ValueError
                        raise RuntimeError(f"aws kms sign output not base64: {e}")
                last_err = (proc.stderr or proc.stdout or "").strip()
                if _kms_permanent(last_err):
                    break
            if attempt < _KMS_SIGN_RETRIES:
                time.sleep(0.5 * attempt)
        raise RuntimeError(
            f"aws kms sign failed after {_KMS_SIGN_RETRIES} attempt(s): {last_err} "
            "— evidence signing is fail-closed (NOT downgraded to unsigned); the run "
            "aborts so no misleadingly-unsigned entry is written.")
    finally:
        try:
            os.unlink(msg_path)
        except OSError:
            pass


def _load_kms_signer():
    """Return (sign_fn, alg_label) for the off-host KMS tier if configured, else None.
    Raises RuntimeError if KMS is configured but unusable (e.g. no `aws` CLI) — a
    configured-but-broken signer must fail loud, never silently fall through to a
    weaker tier (DESIGN §15.5)."""
    key_id = os.environ.get(_KMS_KEY_ENV, "").strip()
    if not key_id:
        return None
    aws = shutil.which(os.environ.get(_AWS_BIN_ENV, "").strip() or "aws")
    if not aws:
        raise RuntimeError(
            f"{_KMS_KEY_ENV} is set but the AWS CLI ('aws') is not on PATH; KMS signing "
            f"needs it (install AWS CLI v2 or set {_AWS_BIN_ENV}). Refusing to silently "
            "downgrade to a weaker/unsigned tier.")
    profile = os.environ.get(_KMS_PROFILE_ENV, "").strip()
    region = os.environ.get(_KMS_REGION_ENV, "").strip() or _region_from_arn(key_id)
    base_cmd = [aws, "kms", "sign", "--key-id", key_id,
                "--message-type", "RAW", "--signing-algorithm", _KMS_SIGN_ALG,
                "--output", "text", "--query", "Signature"]
    if profile:
        base_cmd += ["--profile", profile]
    if region:
        base_cmd += ["--region", region]

    def _sign(entry_hash_hex):
        return _kms_sign(base_cmd, entry_hash_hex)

    return _sign, _KMS_ALG_LABEL


def _load_signer():
    """Resolve the active signer in priority order: KMS (off-host) → local ECDSA →
    HMAC → none. A configured-but-broken higher tier raises (fail-closed); an
    unconfigured tier falls through."""
    global _warned_unsigned
    kms_signer = _load_kms_signer()
    if kms_signer:
        return kms_signer
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
              f"{_KMS_KEY_ENV} (KMS off-host, strongest), {_EC_KEY_ENV} (local ECDSA), "
              f"or {_HMAC_KEY_ENV} (HMAC) to sign. "
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


def _load_ec_verifier():
    """Return an ec_verify(sig_hex, msg_ascii_bytes)->bool for offline ECDSA
    verification if VULNTRIAGE_EVIDENCE_EC_PUBKEY names a PEM public key AND
    `cryptography` is importable, else None. The public key is exported once from
    KMS (`aws kms get-public-key`) or the local private key, so verification never
    needs AWS/network. Raises (OSError/ValueError) if the pubkey is set but unreadable
    — verify() surfaces that rather than silently skipping the signature check."""
    path = os.environ.get(_EC_PUBKEY_ENV, "").strip()
    if not path:
        return None
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return None
    with open(path, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())

    def ec_verify(sig_hex, msg):
        try:
            pub.verify(bytes.fromhex(sig_hex or ""), msg, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            return False

    return ec_verify


def verify(path):
    """Re-walk the log and check the hash chain, HMAC sigs (when the shared secret is
    set), and ECDSA sigs (when VULNTRIAGE_EVIDENCE_EC_PUBKEY + `cryptography` are
    available — covers both the local-PEM and KMS tiers, which sign identically).
    Returns (ok:bool, checked:int, error:str|None). Without the pubkey, ECDSA sigs are
    structurally-present-only and the chain remains authoritative for tamper-evidence.
    Intended for tests / an audit command."""
    if not os.path.exists(path):
        return True, 0, None
    try:
        ec_verify = _load_ec_verifier()
    except (OSError, ValueError) as e:
        return False, 0, f"cannot load EC public key ({_EC_PUBKEY_ENV}): {e}"
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
            alg = obj.get("sig_alg", "")
            if alg == "HMAC-SHA256" and hmac_secret:
                want_sig = hmac.new(hmac_secret, obj["entry_hash"].encode("ascii"),
                                    hashlib.sha256).hexdigest()
                if not hmac.compare_digest(want_sig, obj.get("sig", "")):
                    return False, checked, f"HMAC mismatch at seq {obj['seq']}"
            if ec_verify and alg.startswith(_ECDSA_ALG_LABEL):
                if not ec_verify(obj.get("sig", ""), obj["entry_hash"].encode("ascii")):
                    return False, checked, f"ECDSA signature mismatch at seq {obj['seq']}"
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
