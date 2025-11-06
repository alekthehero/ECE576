import re, os, sys, math, itertools, argparse, base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import time

BACKEND = default_backend()
ALPHABET_25 = "abcdefghiklmnopqrstuvwxyz"

def read_text(fn: str) -> str:
    with open(fn, "r", encoding="utf-8") as f:
        return f.read()

def write_text(fn: str, data: str):
    with open(fn, "w", encoding="utf-8") as f:
        f.write(data)

def format_time(seconds: float) -> str:
    if seconds >= 60:
        m, s = divmod(seconds, 60)
        return f"{int(m)}m {s:.2f}s"
    return f"{seconds:.2f}s"

def norm(s: str) -> str:
    s = s.lower()
    s = re.sub(r'[^a-z]', '', s)
    s = s.replace('j', 'i')
    return s

def make_digraphs(plain: str) -> list[str]:
    p = norm(plain)
    out = []
    i = 0
    while i < len(p):
        a = p[i]
        b = p[i + 1] if i + 1 < len(p) else ''
        if b == '':
            out.append(a + 'x'); i += 1
        elif a == b:
            out.append(a + 'x'); i += 1
        else:
            out.append(a + b); i += 2
    return out

def key_square(key_letters: str) -> list[list[str]]:
    key_letters = norm(key_letters)
    seen = set(); out = ''
    for ch in key_letters:
        if ch in ALPHABET_25 and ch not in seen:
            seen.add(ch); out += ch
    out += ''.join(c for c in ALPHABET_25 if c not in seen)
    return [list(out[i:i + 5]) for i in range(0, 25, 5)]

def pos(M: list[list[str]], ch: str) -> tuple[int, int]:
    for r in range(5):
        for c in range(5):
            if M[r][c] == ch:
                return r, c
    raise ValueError(f"char {ch} not found")

def pf_encrypt(key_letters: str, plaintext: str) -> str:
    pairs = make_digraphs(plaintext)
    M = key_square(key_letters)
    ct = []
    for a, b in pairs:
        ra, ca = pos(M, a); rb, cb = pos(M, b)
        if ra == rb:
            ct += [M[ra][(ca + 1) % 5], M[rb][(cb + 1) % 5]]
        elif ca == cb:
            ct += [M[(ra + 1) % 5][ca], M[(rb + 1) % 5][cb]]
        else:
            ct += [M[ra][cb], M[rb][ca]]
    return ''.join(ct)

def pf_decrypt(key_letters: str, ciphertext: str) -> str:
    c = norm(ciphertext)
    if len(c) % 2:
        c = c[:-1]
    M = key_square(key_letters)
    pt = []
    for i in range(0, len(c), 2):
        a, b = c[i], c[i + 1]
        ra, ca = pos(M, a); rb, cb = pos(M, b)
        if ra == rb:
            pt += [M[ra][(ca - 1) % 5], M[rb][(cb - 1) % 5]]
        elif ca == cb:
            pt += [M[(ra - 1) % 5][ca], M[(rb - 1) % 5][cb]]
        else:
            pt += [M[ra][cb], M[rb][ca]]
    return ''.join(pt)

def encrypt_test_plain(key_letters: str, plain_path: str, out_path: str = "test_enc_generated.txt"):
    plain = read_text(plain_path)
    enc = pf_encrypt(key_letters, plain)
    write_text(out_path, enc)
    print(f"Encrypted {plain_path} using key '{key_letters}' → wrote {out_path}")


NUM_TO_WORD = {
    "0": "zero", "1": "one", "2": "two", "3": "three", "4": "four",
    "5": "five", "6": "six", "7": "seven", "8": "eight", "9": "nine"
}

def derive_base_letters(cnum: str, first_n: int = 10) -> str:
    out = ""
    seen = set()
    for d in cnum:
        if d not in NUM_TO_WORD:
            continue
        for ch in NUM_TO_WORD[d]:
            if ch not in seen:
                seen.add(ch)
                out += ch
            if len(out) >= first_n:
                return out
    return out[:first_n]

def load_glossary(fn: str) -> set[str]:
    words = set()
    for line in read_text(fn).splitlines():
        w = re.sub(r'[^a-z]', '', line.lower())
        if w:
            words.add(w)
    return words

# --- supports full glossary search ---
def count_block_matches(decrypted_block: str, glossary: set[str], word_len: int, full_search=False) -> int:
    tokens = re.findall(r'[a-z]+', decrypted_block)
    seen = set(); hits = 0
    if full_search:
        for t in tokens:
            if t in glossary and t not in seen:
                seen.add(t)
                hits += 1
        return hits
    for t in tokens:
        if (word_len <= 4 and len(t) == word_len) or (word_len > 4 and len(t) >= 5):
            if t in glossary and t not in seen:
                seen.add(t)
                hits += 1
    return hits

def stage_filter_candidates(keys: list[str], cipher: str, glossary: set[str], threshold: int, word_len: int, full_search=False, block_size=20) -> list[str]:
    kept = []
    for k in keys:
        try:
            full_dec = pf_decrypt(k, cipher)
            segment = full_dec[:block_size]
        except Exception:
            continue
        hits = count_block_matches(segment, glossary, word_len, full_search)
        if hits >= threshold:
            kept.append(k)
    return kept


def derive_fernet_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200000, backend=BACKEND)
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)

def save_key_encrypted(key_letters: str, out_path: str):
    pw = input("Enter password to encrypt saved key: ").strip()
    salt = os.urandom(16)
    fk = derive_fernet_key(pw, salt)
    f = Fernet(fk)
    token = f.encrypt(key_letters.encode("utf-8"))
    write_text(out_path, salt.hex() + ":" + token.decode("utf-8"))
    print("Encrypted key saved to", out_path)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cnum", required=True)
    ap.add_argument("--cipherfile", default="alek.txt")
    ap.add_argument("--test_plain", default="test_plain.txt")
    ap.add_argument("--test_enc", default="test_enc.txt")
    ap.add_argument("--glossary", default="glossary.txt")
    ap.add_argument("--block_size", type=int, default=10)
    ap.add_argument("--threshold", type=int, default=1)
    ap.add_argument("--max_perms", type=int, default=None)
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--save_key", action="store_true")
    ap.add_argument("--gen_enc", action="store_true", help="Generate encrypted text from test_plain.txt and exit")
    args = ap.parse_args()

    if args.gen_enc:
        encrypt_test_plain("key", args.test_plain)
        sys.exit(0)

    if args.quick:
        args.max_perms = min(args.max_perms or 20000, 20000)

    plain = read_text(args.test_plain)
    enc_expected = read_text(args.test_enc)
    enc_calc = pf_encrypt("key", plain)
    dec_calc = pf_decrypt("key", enc_expected)
    print("Self-test enc==expected:", enc_calc == enc_expected.strip())
    print("Self-test dec==plain:", dec_calc == norm(plain))

    cipher = norm(read_text(args.cipherfile))
    glossary = load_glossary(args.glossary)
    base_letters = derive_base_letters(args.cnum, 10)
    print("Base letters:", base_letters, f"(len={len(base_letters)})")
    total = math.factorial(len(base_letters))
    print("Total permutations (full):", total)

    if not args.max_perms:
        args.max_perms = total

    word_len = 2

    start_time = time.perf_counter()
    stage_start = time.perf_counter()
    print(f"\nStage 1 — testing up to {args.max_perms} permutations on first {args.block_size} chars with threshold={args.threshold}, looking for {word_len}-letter words.")
    perms = itertools.islice(itertools.permutations(base_letters), args.max_perms)
    keys_all = ["".join(p) for p in perms]
    candidates = stage_filter_candidates(keys_all, cipher, glossary, args.threshold, word_len)
    print(f"Completed Stage 1: tested={len(keys_all)} | candidates={len(candidates)}")
    stage_elapsed = time.perf_counter() - stage_start
    total_elapsed = time.perf_counter() - start_time
    print(f"⏱ Stage 1 time: {format_time(stage_elapsed)} | Total: {format_time(total_elapsed)}\n")

    if len(candidates) == 0:
        print("⚠ No candidates currently found")

    stage = 2
    while True:
        if len(candidates) == 1:
            best = candidates[0]
            print("Single candidate key found.")
            full_plain = pf_decrypt(best, cipher)
            print("\n=== KEY ===\n", best)
            print("\n=== DECRYPT (first 500 chars) ===\n", full_plain[:500])
            write_text("decrypted.txt", full_plain)
            print("Full plaintext written to decrypted.txt")
            if args.save_key:
                save_key_encrypted(best, "found_key.enc")
            break

        try:
            choice = input("Type 'o' to OUTPUT candidates, 'c' to CONTINUE refining, or 'q' to quit: ").strip().lower()
        except EOFError:
            choice = 'c'

        if choice == 'o':
            out_fn = f"candidates_stage{stage-1}.txt"
            write_text(out_fn, "\n".join(candidates))
            print("Wrote", out_fn)
            cont = input("Continue refining? (y/n): ").strip().lower()
            if cont != 'y':
                break
        elif choice == 'q':
            break

        word_len += 1
        full_search = False
        if word_len >= 5:
            print("Stage 5 — performing full glossary search (all word lengths).")
            full_search = True

        print(f"\nStage {stage} — refining with threshold={args.threshold}, "
              f"{'FULL GLOSSARY SEARCH' if full_search else f'looking for {word_len}-letter words'}.")

        if len(candidates) == 0:
            candidates = keys_all.copy()

        candidates = stage_filter_candidates(candidates, cipher, glossary, args.threshold, word_len, full_search)
        print(f"Completed Stage {stage}: candidates={len(candidates)}")
        stage_elapsed = time.perf_counter() - stage_start
        total_elapsed = time.perf_counter() - start_time
        print(f"⏱ Stage {stage} time: {format_time(stage_elapsed)} | Total: {format_time(total_elapsed)}\n")

        if len(candidates) == 0:
            print("⚠ No candidates currently found\n")

        stage += 1

        if 20 >= len(candidates) > 0:
            print("\n<= 20 candidates. Writing preview file for review.")
            previews = []
            for k in candidates:
                dec = pf_decrypt(k, cipher)[:400]
                previews.append(f"KEY {k}\n{dec}\n")
            write_text("candidate_previews.txt", "\n".join(previews))
            print("Wrote candidate_previews.txt")
            break

        if word_len > 5:
            print("Reached final stage (Stage 5). Ending search.")
            break

if __name__ == "__main__":
    main()
