#!/usr/bin/env python3
"""Redaction guard for logs.

Fails if a logging / printing call interpolates a secret-bearing value. The hard
rule (see SECURITY.md "Logging and redaction"): logs carry metadata only — never
private keys, passphrases, the master password, the Secret Key, tokens, vault
plaintext, or full crypto blobs.

This is a heuristic, *identifier-based* check: it flags a log/print/format call
whose argument span mentions a known secret-bearing identifier (e.g. `secret_key`,
`expose_bytes`, `refresh_token`). It can't prove redaction, but it catches the
obvious mistakes that manual review would otherwise be the only guard against —
so a careless future log of a secret fails CI instead of shipping.

Limitations — it is a backstop, NOT a proof; code review remains the primary guard:
  - It only inspects a call's own argument span, so laundering a secret through a
    temporary defeats it. `format!`/`format_args!` are scanned, so the *into-string*
    step `let m = format!("{}", secret_key); log!("{m}")` IS caught — but a plain
    `let x = secret_key; log!("{x}")` rename is not (that needs data-flow analysis).
  - Paren-balancing skips `"`/`` ` ``-delimited strings, but not `'` ones (Rust
    lifetime ambiguity); a `)` inside a single-quoted string can truncate the span
    early. Such truncation only ever causes a miss, never a false CI failure.

Run by `just lint-logs` and in CI (.github/workflows/ci.yml).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ROOTS = ["rust-core/crates", "client/src-tauri/src", "server/src", "client/src"]
EXTS = {".rs", ".ts", ".tsx"}
# Test code legitimately constructs/handles secrets; build output is generated.
SKIP = re.compile(r"(^|/)(tests?|node_modules|target|dist|gen)(/|$)|tests\.rs$|\.test\.")

# Call heads whose arguments must be secret-free. Group 1 is the call name.
# `format!`/`format_args!` are included because building a string from a secret is
# the usual first step of leaking one into a log/panic.
LOG_HEAD = re.compile(
    r"\b("
    r"log::(?:error|warn|info|debug|trace)"
    r"|tracing::(?:error|warn|info|debug|trace|event)"
    r"|eprintln|println|eprint|print|dbg|format|format_args"
    r"|logError|logWarn|logInfo|logDebug"
    r"|console\.(?:log|error|warn|info|debug)"
    r")\s*!?\s*\("
)

# Secret-bearing IDENTIFIERS. Word-boundary matched, so prose with spaces
# ("Secret Key", "refresh token") and unrelated names ("derive_db_key") don't trip.
# Mirrors the Zeroizing-wrapped secrets in rust-core/crates/{crypto,keychain,ffi}
# (key bytes, KDF/PAKE inputs, passwords, tokens) — extend when new secret types land.
DENY = re.compile(
    r"\b("
    r"expose_bytes|expose_to_bytes|expose_secret"
    r"|secret_key|secretKey|secret_key_hex|secretKeyHex|secret_bytes|sk_bytes"
    r"|x_secret|e_secret|spake_key|device_secret"
    r"|wrapped_keyset|private_key|privateKey|db_key|cleanKey|passphrase"
    r"|refresh_token|refreshToken|access_token|accessToken"
    r"|master_password|masterPassword|old_password|new_password"
    r")\b"
)


def arg_span(text: str, open_idx: int) -> str:
    """Substring inside the balanced parens that start at `open_idx` ('('),
    spanning newlines so multi-line log!(...) calls are checked as a whole.
    Skips `"`/`` ` ``-delimited string literals (with backslash escapes) so a
    paren inside a string can't end the span early. `'` is left alone — in Rust
    it's mostly a lifetime, not a string — at the cost of an occasional early
    cut-off inside single-quoted strings (a miss, never a false positive)."""
    depth = 0
    quote = None  # active string delimiter, or None
    i, n = open_idx, len(text)
    while i < n:
        c = text[i]
        if quote is not None:
            if c == "\\":
                i += 2  # skip the escaped char
                continue
            if c == quote:
                quote = None
        elif c == '"' or c == "`":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i]
        i += 1
    return text[open_idx + 1 :]


def line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def check(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    hits = []
    for m in LOG_HEAD.finditer(text):
        span = arg_span(text, m.end() - 1)  # m.end()-1 is the '(' from \(
        d = DENY.search(span)
        if d:
            hits.append(
                f"{path.relative_to(REPO)}:{line_of(text, m.start())}: "
                f"`{m.group(1)}` call mentions secret-bearing `{d.group(1)}`"
            )
    return hits


def main() -> int:
    failures: list[str] = []
    for root in ROOTS:
        for p in sorted((REPO / root).rglob("*")):
            if p.suffix not in EXTS or not p.is_file():
                continue
            if SKIP.search(str(p.relative_to(REPO))):
                continue
            failures += check(p)

    if failures:
        print(
            "Log redaction guard FAILED — secrets must never be logged "
            "(see SECURITY.md \"Logging and redaction\"):\n",
            file=sys.stderr,
        )
        for f in failures:
            print("  " + f, file=sys.stderr)
        print(
            f"\n{len(failures)} suspicious call(s). If a flagged value is provably "
            "non-secret, rename it or refactor so the log carries metadata only.",
            file=sys.stderr,
        )
        return 1

    print("Log redaction guard: OK — no secret-bearing identifier in any log/print call.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
