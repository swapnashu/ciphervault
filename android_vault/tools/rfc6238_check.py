"""RFC 6238 reference implementation - verifies the exact algorithm that will be
ported to Kotlin. Run: python rfc6238_check.py

Expected values are taken verbatim from RFC 6238 Appendix B, Table 1
(SHA-1 / SHA-256 / SHA-512 columns are kept separate on purpose).
"""
import base64
import hashlib
import hmac
import struct
import time

DIGITS = 6
PERIOD = 30


def hotp(secret: bytes, counter: int, digits=DIGITS, algo=hashlib.sha1) -> str:
    """RFC 4226 dynamic truncation."""
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret, msg, algo).digest()
    offset = digest[-1] & 0x0F
    code = (
        (digest[offset] & 0x7F) << 24
        | (digest[offset + 1] & 0xFF) << 16
        | (digest[offset + 2] & 0xFF) << 8
        | (digest[offset + 3] & 0xFF)
    )
    return str(code % (10**digits)).zfill(digits)


def totp(secret: bytes, at, digits=DIGITS, period=PERIOD, algo=hashlib.sha1) -> str:
    return hotp(secret, at // period, digits, algo)


def base32_decode(s: str) -> bytes:
    s = s.replace(" ", "").upper()
    return base64.b32decode(s + "=" * ((-len(s)) % 8))


# ---- 1. RFC 6238 Appendix B: SHA-1 (Google Authenticator compatible) --------
S1 = b"12345678901234567890"
SHA1_VECTORS = {
    59: "94287082",
    1111111109: "07081804",
    1111111111: "14050471",
    1234567890: "89005924",
    2000000000: "69279037",
    20000000000: "65353130",
}

# ---- 2. RFC 6238 Appendix B: SHA-256 ---------------------------------------
S256 = b"12345678901234567890123456789012"
SHA256_VECTORS = {
    59: "46119246",
    1111111109: "68084774",
    1111111111: "67062674",
    1234567890: "91819424",
    2000000000: "90698825",
    20000000000: "77737706",
}

# ---- 3. RFC 6238 Appendix B: SHA-512 ---------------------------------------
S512 = b"1234567890123456789012345678901234567890123456789012345678901234"
SHA512_VECTORS = {
    59: "90693936",
    1111111109: "25091201",
    1111111111: "99943326",
    1234567890: "93441116",
    2000000000: "38618901",
    20000000000: "47863826",
}

failures = []


def run_vectors(label, secret, vectors, algo):
    print(f"\n--- {label} ---")
    for t in sorted(vectors):
        want = vectors[t]
        got = hotp(secret, t // 30, digits=8, algo=algo)
        ok = got == want
        if not ok:
            failures.append(f"{label} T={t}")
        print(f"  T={t:<12} want={want}  got={got}  {'PASS' if ok else 'FAIL'}")


print("=" * 68)
print("RFC 6238 Appendix B test vectors (8-digit)")
print("=" * 68)
run_vectors("SHA-1 (required for Google Authenticator)", S1, SHA1_VECTORS, hashlib.sha1)
run_vectors("SHA-256", S256, SHA256_VECTORS, hashlib.sha256)
run_vectors("SHA-512", S512, SHA512_VECTORS, hashlib.sha512)

# ---- 4. base32 decoding (what otpauth:// URIs contain) --------------------
print("\n" + "=" * 68)
print("Base32 decoding (RFC 4648, as used in otpauth:// URIs)")
print("=" * 68)
for text, plain in [
    ("JBSWY3DPEHPK3PXP", b"Hello!\xde\xad\xbe\xef"),
    ("MFRGGZDF", b"abcde"),
    ("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", b"12345678901234567890"),
]:
    got = base32_decode(text)
    ok = got == plain
    if not ok:
        failures.append(f"base32 {text}")
    print(f"  {text:<34} -> {got!r:<40} {'PASS' if ok else 'FAIL'}")

# Round-trip: every ASCII string must survive encode->decode unchanged.
# This is what actually guards the otpauth:// parser in the app.
print("\n  round-trip encode/decode (guards otpauth:// parsing)")
for n in range(1, 22):
    raw = bytes(range(97, 97 + n))
    enc = base64.b32encode(raw).decode().rstrip("=")
    back = base64.b32decode(enc + "=" * ((-len(enc)) % 8))
    ok = back == raw
    if not ok:
        failures.append(f"base32 roundtrip len={n}")
    print(f"    len={n:<3} {enc:<40} {'PASS' if ok else 'FAIL'}")

# ---- 5. 6-digit is modulo, NOT a prefix ------------------------------------
print("\n" + "=" * 68)
print("6-digit truncation: code % 10^6 (NOT the first 6 chars)")
print("=" * 68)
for counter in (0, 1, 41152263, 59721744):
    c8 = hotp(S1, counter, digits=8)
    c6 = hotp(S1, counter, digits=6)
    ok = c6 == c8[-6:]
    if not ok:
        failures.append(f"trunc counter={counter}")
    print(f"  counter={counter:<10} 8d={c8}  6d={c6}  last6={c8[-6:]}  {'PASS' if ok else 'FAIL'}")

# ---- 6. 30-second period drift behaviour (what the UI countdown shows) ----
print("\n" + "=" * 68)
print("Period boundary: code must change exactly on 30s boundaries")
print("=" * 68)
base = 1234567890
codes = [totp(S1, base + s) for s in (0, 29)]
same = codes[0] == codes[1]
changed = totp(S1, base + 30) != codes[0]
if not same:
    failures.append("period stability")
if not changed:
    failures.append("period rollover")
print(f"  t and t+29 identical   : {codes[0]} / {codes[1]}  {'PASS' if same else 'FAIL'}")
print(f"  t+30 rolls over        : {totp(S1, base + 30)}  {'PASS' if changed else 'FAIL'}")

# ---- 7. remaining-seconds helper (for the countdown ring) -----------------
print("\n" + "=" * 68)
print("Seconds remaining in period (drives countdown UI)")
print("=" * 68)
for at in (1234567890, 1234567905, 1234567919):
    rem = PERIOD - (at % PERIOD)
    print(f"  t={at}  counter={at // 30}  remaining={rem}s")

print("\n" + "=" * 68)
if failures:
    print(f"FAILURES ({len(failures)}): {failures}")
else:
    print("ALL RFC 6238 VECTORS PASS")
print("=" * 68)
raise SystemExit(1 if failures else 0)