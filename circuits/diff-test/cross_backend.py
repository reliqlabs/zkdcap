#!/usr/bin/env python3
"""Cross-backend differential test (partial-Z6, intent 4.7).

Runs the SAME (quote, collateral, timestamp) through both circuits and asserts the
decoded journal field-VALUES are equal (not bytes — the two backends use different
public-input encodings; see .colosseum/diff-test-plan.md check 3). This is the
buildable-now half of the harness; the dcap-qvl oracle (checks 1-2) is a follow-up
that needs the git dependency.

  python3 circuits/diff-test/cross_backend.py

Requires nargo + bb on PATH (or under ~/.nargo/bin and ~/.bb-v4.0.4) and a Go toolchain.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FIX = os.path.join(ROOT, "circuits/dcap-gnark/testdata/fixtures/zkdcap")
QUOTE = os.path.join(FIX, "quote.bin")
COLL = os.path.join(FIX, "collateral.json")
NOIR = os.path.join(ROOT, "circuits/dcap-noir")
GNARK = os.path.join(ROOT, "circuits/dcap-gnark")
TIMESTAMP = "1751624163"  # 2025-07-04, inside the fixture's ~30-day window

os.environ["PATH"] = (
    os.path.expanduser("~/.nargo/bin") + ":" +
    os.path.expanduser("~/.bb-v4.0.4") + ":" + os.environ["PATH"]
)


def run(cmd, cwd=None, capture=True):
    return subprocess.run(cmd, cwd=cwd, capture_output=capture, text=True)


def gnark_journal():
    r = run(["go", "run", "./cmd/journal", "-quote", QUOTE, "-collateral", COLL,
             "-timestamp", TIMESTAMP], cwd=GNARK)
    if r.returncode != 0:
        sys.exit("gnark journal failed:\n" + r.stderr)
    return json.loads(r.stdout)


# Noir public-input layout (must match crates/dcap/src/main.nr output array): each
# field is a 32-byte big-endian BN254 element. (field_index_1based, byte_widths).
NOIR_LAYOUT = [
    ("mr_td", [31, 17]),
    ("rtmr0", [31, 17]),
    ("rtmr1", [31, 17]),
    ("rtmr2", [31, 17]),
    ("rtmr3", [31, 17]),
    ("report_data", [31, 31, 2]),
    ("tcb_status", None),
    ("timestamp", None),
    ("cert_serial", [20]),
    ("fmspc", [6]),
    ("tcb_info_eval_num", None),
    ("qe_id_eval_num", None),
    ("valid_from", None),
    ("valid_until", None),
]


def noir_journal():
    gen = os.path.join(GNARK, "..", "dcap-noir", "tools")
    # build genprover + generate honest Prover.toml
    tmp = tempfile.mkdtemp()
    genbin = os.path.join(tmp, "genprover")
    r = run(["go", "build", "-o", genbin, "genprover.go", "toml.go"], cwd=os.path.join(NOIR, "tools"))
    if r.returncode != 0:
        sys.exit("genprover build failed:\n" + r.stderr)
    prover = os.path.join(NOIR, "crates/dcap/Prover.toml")
    with open(prover, "w") as f:
        r = run([genbin, "-quote", QUOTE, "-collateral", COLL, "-timestamp", TIMESTAMP], capture=True)
        if r.returncode != 0:
            sys.exit("genprover failed:\n" + r.stderr)
        f.write(r.stdout)
    # execute + prove -> public_inputs
    r = run(["nargo", "execute"], cwd=os.path.join(NOIR, "crates/dcap"))
    if r.returncode != 0:
        sys.exit("nargo execute failed:\n" + r.stderr)
    vkdir = os.path.join(tmp, "vk"); os.makedirs(vkdir, exist_ok=True)
    pdir = os.path.join(tmp, "proof"); os.makedirs(pdir, exist_ok=True)
    target = os.path.join(NOIR, "target/dcap_full.json")
    wit = os.path.join(NOIR, "target/dcap_full.gz")
    run(["bb", "write_vk", "-s", "ultra_honk", "-b", target, "-o", vkdir])
    run(["bb", "prove", "-s", "ultra_honk", "-b", target, "-w", wit,
         "-k", os.path.join(vkdir, "vk"), "-o", pdir])
    pi = os.path.join(pdir, "public_inputs")
    raw = open(pi, "rb").read()
    fields = [int.from_bytes(raw[i:i+32], "big") for i in range(0, len(raw), 32)]
    shutil.rmtree(tmp, ignore_errors=True)

    j, fi = {}, 0
    for name, widths in NOIR_LAYOUT:
        if widths is None:
            j[name] = str(fields[fi]); fi += 1
        else:
            b = b"".join(fields[fi + k].to_bytes(w, "big") for k, w in enumerate(widths))
            j[name] = b.hex(); fi += len(widths)
    return j


def main():
    print("== cross-backend differential test (Noir UltraHonk vs gnark Groth16) ==")
    g = gnark_journal()
    n = noir_journal()
    keys = [k for k, _ in NOIR_LAYOUT]
    ok = True
    for k in keys:
        match = g[k] == n[k]
        ok &= match
        flag = "OK  " if match else "FAIL"
        print(f"  [{flag}] {k:18} gnark={g[k]}  noir={n[k]}")
    print("\nRESULT:", "PASS — journals field-value-identical across backends" if ok
          else "FAIL — backend divergence (intent 4.7 bug)")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
