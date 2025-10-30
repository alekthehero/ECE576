import os
import sys
import time
import argparse
import itertools
import base64
import random
import string
import math
from typing import Tuple, Dict, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

backend = default_backend()

DICT_DEFAULT = os.path.join(os.path.dirname(__file__) or ".", "dictionary.txt")
ALPHABET = string.ascii_uppercase
PW_LEN = 5
TOTAL = 26 ** PW_LEN

# Had AI write some helpers for estimating size and printing in a nicer format
def estimate_size_per_line():
    return 44 + 1 + PW_LEN + 1

def human_readable(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024.0:
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} PB"


def estimate_dictionary_size() -> int:
    return estimate_size_per_line() * TOTAL


def hash_to_b64(s: str) -> str:
    # Use the cryptography library's SHA256 hasher (same as Lab2/message_digest.py)
    hasher = hashes.Hash(hashes.SHA256(), backend)
    hasher.update(s.encode("utf-8"))
    digest = hasher.finalize()
    return base64.b64encode(digest).decode("ascii")


# Core func
def generate_dictionary(path: str, full: bool = False, sample: int = 100_000, force: bool = False):
    if os.path.exists(path) and not force:
        print(f"Dictionary already exists at {path}, skipping generation. Use --generate to force.")
        return

    if not full and sample <= 0:
        raise ValueError("sample must be > 0 when not generating full dictionary")
    if not full and sample > TOTAL:
        print(f"Warning: sample ({sample}) > TOTAL ({TOTAL}), capping to TOTAL.")
        sample = TOTAL

    total = TOTAL if full else sample
    print(f"Generating dictionary at {path} with {total} entries ({'full' if full else 'sample'})")

    dirpath = os.path.dirname(path) or "."
    os.makedirs(dirpath, exist_ok=True)

    written = 0
    with open(path, "w", encoding="ascii") as f:
        for tpl in itertools.product(ALPHABET, repeat=PW_LEN):
            pw = "".join(tpl)
            f.write(f"{hash_to_b64(pw)} {pw}\n")
            written += 1
            if written % 1_000_000 == 0:
                print(f"  written {written} entries...")
            if not full and written >= sample:
                break

    print(f"Done. Wrote {written} entries to {path}")


def dict_linear_search(path: str, target_b64: str) -> Optional[str]:
    with open(path, "r", encoding="ascii") as f:
        for line in f:
            parts = line.rstrip("\n").split(" ", 1)
            if len(parts) != 2:
                continue
            b64, pw = parts
            if b64 == target_b64:
                return pw[:PW_LEN]
    return None


def brute_force_search(target_b64: str) -> Optional[str]:
    for tpl in itertools.product(ALPHABET, repeat=PW_LEN):
        pw = "".join(tpl)
        if hash_to_b64(pw) == target_b64:
            return pw
    return None

def run_trials(dict_path: str, trials: int = 3):
    if trials <= 0:
        raise ValueError("trials must be > 0")

    dict_times = []
    bf_times = []
    for i in range(trials):
        pw = "".join(random.choices(ALPHABET, k=PW_LEN))
        target_b64 = hash_to_b64(pw)
        print(f"\nTrial {i+1}: password={pw}")

        t_start = time.perf_counter()
        found_pw = dict_linear_search(dict_path, target_b64)
        t_end = time.perf_counter()
        dict_elapsed = t_end - t_start
        if found_pw != pw:
            print(f"  ERROR: dictionary search returned {found_pw!r} expected {pw!r}")
        else:
            print(f"  dictionary linear search time: {dict_elapsed:.6f} s")

        t_start_b = time.perf_counter()
        bf_pw = brute_force_search(target_b64)
        t_end_b = time.perf_counter()
        bf_elapsed = t_end_b - t_start_b
        if bf_pw != pw:
            print(f"  ERROR: brute force found {bf_pw!r} expected {pw!r}")
        else:
            print(f"  brute-force time: {bf_elapsed:.6f} s")

        dict_times.append(dict_elapsed)
        bf_times.append(bf_elapsed)

    avg_dict = sum(dict_times) / len(dict_times)
    avg_bf = sum(bf_times) / len(bf_times)
    print("\nAverage times over {} trials:".format(trials))
    print(f"  dictionary linear average: {avg_dict:.6f} s")
    print(f"  brute-force average:       {avg_bf:.6f} s")
    return avg_dict, avg_bf

RAINBOW_DEFAULT = os.path.join(os.path.dirname(__file__) or ".", "rainbow.txt")
DEFAULT_CHAIN_LEN = 10
DEFAULT_SAMPLE_PCT = 0.10  # 10% of passwords as starting points


def reduction_from_b64(b64_str: str, round_idx: int = 0) -> str:
    out = []
    for i in range(PW_LEN):
        ch = b64_str[i % len(b64_str)]
        val = (ord(ch) + round_idx) % 26
        out.append(ALPHABET[val])
    return ''.join(out)


def build_chain(start_pw: str, chain_len: int = DEFAULT_CHAIN_LEN) -> Tuple[str, str]:
    pw = start_pw
    for i in range(chain_len):
        h = hash_to_b64(pw)
        pw = reduction_from_b64(h, round_idx=i)
    return start_pw, pw


def generate_rainbow(path: str, chain_len: int = DEFAULT_CHAIN_LEN, sample_pct: float = DEFAULT_SAMPLE_PCT,
                     force: bool = False, max_chains: int = None):
    if os.path.exists(path) and not force:
        print(f"Rainbow table already exists at {path}, skipping. Use --generate --force to overwrite.")
        return

    if not (0.0 < sample_pct <= 1.0):
        raise ValueError("sample_pct must be between 0 (exclusive) and 1.0 (inclusive)")

    stride = max(1, int(round(1.0 / sample_pct)))
    expected_chains = math.ceil(TOTAL / stride)
    if max_chains is not None:
        expected_chains = min(expected_chains, max_chains)

    print(f"Generating rainbow table at {path}")
    print(f"  chain_len={chain_len}, sample_pct={sample_pct:.4f}, stride={stride}, expected_chains≈{expected_chains}")

    dirpath = os.path.dirname(path) or "."
    os.makedirs(dirpath, exist_ok=True)

    written = 0
    idx = 0
    with open(path, "w", encoding="ascii") as f:
        for tpl in itertools.product(ALPHABET, repeat=PW_LEN):
            if idx % stride == 0:
                start_pw = ''.join(tpl)
                start, end = build_chain(start_pw, chain_len=chain_len)
                # store as: end start  (we'll lookup by end)
                f.write(f"{end} {start}\n")
                written += 1
                if written % 100000 == 0:
                    print(f"  written {written} chains...")
                if max_chains is not None and written >= max_chains:
                    break
            idx += 1
            if idx >= TOTAL:
                break

    print(f"Done. Wrote {written} chains to {path}")


def load_rainbow_index(path: str) -> Dict[str, str]:
    idx = {}
    with open(path, "r", encoding="ascii") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) != 2:
                continue
            end, start = parts
            idx[end] = start
    return idx


def rainbow_lookup(rainbow_index: Dict[str, str], target_b64: str, chain_len: int = DEFAULT_CHAIN_LEN) -> Optional[str]:
    for i in range(chain_len - 1, -1, -1):
        temp = target_b64
        pw_candidate = None
        for j in range(i, chain_len):
            pw_candidate = reduction_from_b64(temp, round_idx=j)
            temp = hash_to_b64(pw_candidate)
        # guard against pw_candidate somehow being None (static checker safety)
        if pw_candidate is None:
            continue
        if pw_candidate in rainbow_index:
            start_pw = rainbow_index[pw_candidate]
            pw = start_pw
            for k in range(chain_len):
                h = hash_to_b64(pw)
                if h == target_b64:
                    return pw
                pw = reduction_from_b64(h, round_idx=k)
    return None


def test_rainbow_table(rainbow_path: str, trials: int = 3, chain_len: int = DEFAULT_CHAIN_LEN):
    if not os.path.exists(rainbow_path):
        print(f"Rainbow table not found at {rainbow_path}. Generate it with --rainbow-generate")
        return

    print("Loading rainbow table into memory (end -> start)...")
    idx = load_rainbow_index(rainbow_path)
    print(f"Loaded {len(idx)} chains")

    times_lookup = []
    times_bf = []

    for t in range(trials):
        pw = ''.join(random.choices(ALPHABET, k=PW_LEN))
        target = hash_to_b64(pw)
        print(f"\nTrial {t+1}: target password={pw}")

        ts0 = time.perf_counter()
        recovered = rainbow_lookup(idx, target, chain_len=chain_len)
        ts1 = time.perf_counter()
        lookup_time = ts1 - ts0

        if recovered == pw:
            print(f"  Rainbow lookup succeeded in {lookup_time:.6f}s: {recovered}")
        else:
            print(f"  Rainbow lookup failed (None) in {lookup_time:.6f}s; password not in table or collision")

        tb0 = time.perf_counter()
        bf_res = brute_force_search(target)
        tb1 = time.perf_counter()
        bf_time = tb1 - tb0

        if bf_res != pw:
            print(f"  ERROR: brute-force found {bf_res!r} expected {pw!r}")
        else:
            print(f"  brute-force time: {bf_time:.6f} s")

        times_lookup.append(lookup_time)
        times_bf.append(bf_time)

    print("\nAverage times over trials:")
    print(f"  rainbow lookup average: {sum(times_lookup)/len(times_lookup):.6f} s")
    print(f"  brute-force average:    {sum(times_bf)/len(times_bf):.6f} s")
    return

def main(argv):
    parser = argparse.ArgumentParser(description="Hash dictionary generation and timing")
    parser.add_argument("--generate", action="store_true", help="Generate dictionary file")
    parser.add_argument("--full", action="store_true", help="Generate the full dictionary (26^5 entries)")
    parser.add_argument("--sample", type=int, default=100_000, help="Sample size when not generating full (default 100000)")
    parser.add_argument("--dict", dest="dict_path", default=DICT_DEFAULT, help="Path to dictionary file")
    parser.add_argument("--trials", type=int, default=3, help="Number of timing trials")
    parser.add_argument("--rainbow-generate", action="store_true", help="Generate rainbow table file")
    parser.add_argument("--rainbow-path", default=RAINBOW_DEFAULT, help="Path to rainbow table file")
    parser.add_argument("--rainbow-sample-pct", type=float, default=DEFAULT_SAMPLE_PCT, help="Fraction of passwords to use as chain starts (default 0.10)")
    parser.add_argument("--chain-len", type=int, default=DEFAULT_CHAIN_LEN, help="Rainbow chain length (default 10)")
    parser.add_argument("--rainbow-test", action="store_true", help="Test rainbow table lookups (runs trials)")

    args = parser.parse_args(argv)

    total_est = estimate_dictionary_size()
    print(f"Password space size: 26^{PW_LEN} = {TOTAL}")
    print(f"Estimated dictionary file size (per-line {estimate_size_per_line()} bytes): ~{human_readable(total_est)}")

    if args.generate:
        generate_dictionary(args.dict_path, full=args.full, sample=args.sample, force=True)
    if args.rainbow_generate:
        generate_rainbow(args.rainbow_path, chain_len=args.chain_len, sample_pct=args.rainbow_sample_pct,
                         force=True)
    if args.rainbow_test:
        test_rainbow_table(args.rainbow_path, trials=args.trials, chain_len=args.chain_len)
    if args.trials:
        run_trials(args.dict_path, trials=args.trials)
    else:
        if not os.path.exists(args.dict_path):
            print(f"Dictionary not found at {args.dict_path}. Run with --generate (and optionally --full) to create it.")
            print("For a quick test you can run: python Lab3/task1.py --generate --sample 10000")
            sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
