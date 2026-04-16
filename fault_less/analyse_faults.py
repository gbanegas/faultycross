#!/usr/bin/env python3
"""
LESS BuildGGM Fault Analysis Toolkit
=====================================

Parses output from the fault injection harness (CSV) and the golden
signature dump (text) to identify exploitable leakage.

Attack strategies implemented:
  1. Safe-Error Analysis   — which faults are invisible?
  2. DFA (Differential)    — how do golden vs faulted sigs differ?
  3. Challenge Recovery    — reconstruct the challenge from fault oracles
  4. Tree Topology Mapping — learn the internal GGM structure

Usage:
  python3 analyse_faults.py fault_results.csv [golden_output.txt]
"""

import sys
import csv
import collections
from typing import List, Dict, Tuple

# ── LESS-252-192 parameters ──────────────────────────────────────────
N, K, Q = 252, 126, 127
T, W, S = 192, 36, 2
SEED_LEN = 16  # bytes
NUM_NODES = 2 * T - 1  # 383


def load_csv(path: str) -> List[Dict]:
    """Load the fault injection CSV into a list of dicts."""
    rows = []
    with open(path) as f:
        reader = csv.DictReader(f)
        for r in reader:
            row = {}
            for key in r:
                val = r[key]
                try:
                    row[key] = int(val)
                except ValueError:
                    row[key] = val
            rows.append(row)
    return rows


# =====================================================================
#  Analysis 1: Safe-Error Oracle
# =====================================================================

def safe_error_analysis(rows: List[Dict]):
    """
    SAFE-ERROR ATTACK
    -----------------
    In the standard model (fault during BuildGGM before commitments),
    every fault changes the commitments → changes the challenge →
    produces a NEW valid signature.

    However, the *relationship* between golden and faulted signatures
    leaks information:

    - If a fault at node X causes ZERO change in certain parts of the
      signature, those parts are independent of X's subtree.

    - For each faulted node, we know how many of its descendant leaves
      were published vs. withheld (from the golden challenge). This
      ground-truth lets us validate that the fault oracle is correct.

    MORE IMPORTANTLY: if the fault is injected AFTER the commitment
    phase (between the hash and GGMPath), the challenge stays fixed,
    and a safe-error attack directly reveals challenge positions.
    """
    print("=" * 70)
    print("ANALYSIS 1: Safe-Error / Fault Sensitivity Overview")
    print("=" * 70)

    # Group by level
    by_level = collections.defaultdict(list)
    for r in rows:
        by_level[r["level"]].append(r)

    print(f"\n{'Level':<6} {'Nodes':<7} {'Verify=1':<10} {'SigMatch':<10} "
          f"{'DigestMatch':<12} {'AvgDescLeaves':<14} {'AvgPub':<8} {'AvgWith':<8}")
    print("-" * 75)

    for level in sorted(by_level.keys()):
        grp = by_level[level]
        n = len(grp)
        v1 = sum(1 for r in grp if r["verify_result"] == 1)
        sm = sum(1 for r in grp if r["sig_matches_golden"] == 1)
        dm = sum(1 for r in grp if r["digest_matches"] == 1)
        avg_desc = sum(r["num_descendant_leaves"] for r in grp) / n
        avg_pub  = sum(r["descendant_published"] for r in grp) / n
        avg_with = sum(r["descendant_withheld"] for r in grp) / n
        print(f"{level:<6} {n:<7} {v1:<10} {sm:<10} {dm:<12} "
              f"{avg_desc:<14.1f} {avg_pub:<8.1f} {avg_with:<8.1f}")

    print()
    print("KEY OBSERVATIONS:")
    print("  • If all faults produce verify_result=1 with sig_matches=0,")
    print("    the scheme is self-healing: faults cascade through the hash")
    print("    and produce a new valid challenge, so no safe-error oracle")
    print("    exists at the BuildGGM level in isolation.")
    print()
    print("  • To get a true safe-error oracle, inject faults AFTER the")
    print("    commitment hash (between digest computation and GGMPath).")
    print("    See Analysis 3 for details.")
    print()


# =====================================================================
#  Analysis 2: Differential Fault Analysis
# =====================================================================

def differential_analysis(rows: List[Dict]):
    """
    DFA: WHAT CHANGES BETWEEN GOLDEN AND FAULTED SIGNATURES?
    ---------------------------------------------------------
    Even though both signatures are valid, the attacker observes:
      - Different digest → different challenge string
      - Different seed_storage → different published seeds
      - Different cf_monom_actions → different coset representatives

    The coset representatives involve the SECRET KEY. By collecting many
    (golden, faulted) pairs where the fault targets the same subtree,
    the attacker obtains multiple challenge/response pairs that share
    structural relationships through the secret key.
    """
    print("=" * 70)
    print("ANALYSIS 2: Differential Fault Analysis (DFA)")
    print("=" * 70)
    print()

    # Count leak categories
    categories = collections.Counter(r["leaked_info"] for r in rows)
    print("Fault outcome categories:")
    for cat, cnt in categories.most_common():
        print(f"  {cat}: {cnt}")

    # Correlation: faulting deeper nodes → smaller subtrees → fewer
    # affected leaves → smaller perturbation to commitment hash
    print()
    print("Perturbation size by tree level:")
    print(f"{'Level':<6} {'AvgDescendants':<16} {'DigestChanged':<15} "
          f"{'SeedsChanged':<14}")
    print("-" * 51)

    by_level = collections.defaultdict(list)
    for r in rows:
        by_level[r["level"]].append(r)

    for level in sorted(by_level.keys()):
        grp = by_level[level]
        n = len(grp)
        avg_d = sum(r["num_descendant_leaves"] for r in grp) / n
        dc = sum(1 for r in grp if r["digest_matches"] == 0)
        sc = sum(1 for r in grp if r["seeds_match"] == 0)
        print(f"{level:<6} {avg_d:<16.1f} {dc}/{n:<14} {sc}/{n:<13}")

    print()
    print("DFA ATTACK STRATEGY:")
    print("  1. Collect N faulted signatures for the same message + key")
    print("  2. Each faulted sig has a different challenge string ch'")
    print("  3. For rounds where ch[i]≠0 AND ch'[i]≠0, BOTH signatures")
    print("     contain coset reps derived from the SECRET KEY μ_i")
    print("  4. The relationship: rsp = CosetRep(π·μ_e·τ_{b_i})")
    print("     and              rsp'= CosetRep(π'·μ_e'·τ_{b'_i})")
    print("  5. If b_i = b'_i (same challenge for round i), the τ terms")
    print("     are the same → relationship between rsp and rsp' leaks")
    print("     information about the secret τ_{b_i}")
    print()


# =====================================================================
#  Analysis 3: Challenge Recovery Attack Model
# =====================================================================

def challenge_recovery_analysis(rows: List[Dict]):
    """
    CHALLENGE RECOVERY VIA POST-COMMITMENT FAULT INJECTION
    -------------------------------------------------------
    The most powerful attack targets the seed tree AFTER the commitment
    hash is computed. In the LESS signing flow:

      Step 1: BuildGGM(seed_tree, ...)          ← fault here = DFA
      Step 2: seed_leaves(...)                  ← extract leaves
      Step 3: for i in 0..T-1: compute B(i)    ← commitments
      Step 4: digest = Hash(B(0)||...||B(T-1))  ← challenge fixed
      Step 5: GGMPath(seed_tree, ...)           ← fault HERE for safe-error
      Step 6: for i where ch[i]≠0: CosetRep    ← responses

    If the fault is injected at Step 5 (in the GGMPath extraction):
      - A corrupted seed for a PUBLISHED leaf → verifier recomputes
        wrong commitment → verification FAILS
      - A corrupted seed for a WITHHELD leaf → the seed is never
        transmitted → verification SUCCEEDS (safe error!)

    This directly reveals challenge[i] for the targeted leaf.

    With T=192 and W=36, the challenge has 36 non-zero positions out
    of 192. Learning all positions from safe-error queries requires at
    most 192 signing queries (one per leaf), revealing the full
    challenge. Combined with the coset representatives, this breaks
    the signature.
    """
    print("=" * 70)
    print("ANALYSIS 3: Challenge Recovery (Post-Commitment Fault Model)")
    print("=" * 70)
    print()

    # Simulate: for each node, if we could fault AFTER commitments,
    # would the result be detectable?
    total_nodes = len(rows)
    with_published = sum(1 for r in rows if r["descendant_published"] > 0)
    without_published = sum(1 for r in rows if r["descendant_published"] == 0)

    print(f"Internal nodes tested: {total_nodes}")
    print(f"  Nodes with ≥1 published descendant leaf: {with_published}")
    print(f"  Nodes with 0 published descendants:       {without_published}")
    print()

    if total_nodes > 0:
        # For a post-commitment fault at a node with 0 published descendants,
        # the fault is a safe error → we learn all descendants are withheld
        info_bits = 0
        for r in rows:
            if r["descendant_published"] == 0:
                info_bits += r["num_descendant_leaves"]

        print(f"  Total leaf-challenge bits learnable from safe-error nodes: "
              f"{info_bits}")
        print(f"  (These are leaf positions guaranteed to have challenge ≠ 0)")
        print()

    print("POST-COMMITMENT FAULT ATTACK PROCEDURE:")
    print(f"  1. Binary search the GGM tree (depth ≤ {T.bit_length()} levels)")
    print(f"  2. Fault node → sign → check verify")
    print(f"  3. If verify PASSES → all {W} non-zero challenges are NOT")
    print(f"     in the subtree → refine search to sibling subtree")
    print(f"  4. If verify FAILS → at least one non-zero challenge is")
    print(f"     in the subtree → split and recurse")
    print(f"  5. With ~{T} queries, recover all {W} challenge positions")
    print(f"  6. Combine with coset reps to reconstruct secret key")
    print()
    print("REQUIRED QUERIES (theoretical):")
    print(f"  Lower bound: ⌈log2(C({T},{W}))⌉ = challenge entropy")
    print(f"  Upper bound: {T} (one per leaf)")
    print(f"  Practical:   O({W} · log2({T}/{W})) ≈ {W * (T//W).bit_length()}")
    print()


# =====================================================================
#  Analysis 4: Tree Topology and Propagation
# =====================================================================

def topology_analysis(rows: List[Dict]):
    """
    TREE TOPOLOGY AND FAULT PROPAGATION
    ------------------------------------
    Analyze how faults at different tree levels affect the signature,
    revealing the unbalanced GGM tree structure.
    """
    print("=" * 70)
    print("ANALYSIS 4: GGM Tree Topology and Fault Propagation")
    print("=" * 70)
    print()

    # For LESS-252-192, the tree structure:
    print("LESS-252-192 GGM Tree Structure:")
    print(f"  T = {T} leaves (rounds)")
    print(f"  Tree is NOT a perfect binary tree (T is not a power of 2)")
    print(f"  Total nodes: {NUM_NODES}")
    print(f"  TREE_OFFSETS:           {{0, 0, 0, 0, 0, 0, 0, 0, 128}}")
    print(f"  TREE_NODES_PER_LEVEL:   {{1, 2, 4, 8, 16, 32, 64, 128, 128}}")
    print(f"  TREE_LEAVES_PER_LEVEL:  {{0, 0, 0, 0, 0, 0, 0, 64, 128}}")
    print(f"  TREE_SUBROOTS:          2")
    print()

    # Show propagation fan-out per level
    print("Fault propagation fan-out:")
    print(f"{'Level':<6} {'#Internal':<10} {'MinDesc':<8} {'MaxDesc':<8} "
          f"{'MedianDesc':<10}")
    print("-" * 42)

    by_level = collections.defaultdict(list)
    for r in rows:
        by_level[r["level"]].append(r)

    for level in sorted(by_level.keys()):
        grp = by_level[level]
        descs = sorted([r["num_descendant_leaves"] for r in grp])
        n = len(grp)
        print(f"{level:<6} {n:<10} {descs[0]:<8} {descs[-1]:<8} "
              f"{descs[n//2]:<10}")

    print()
    print("TIMING SIDE-CHANNEL NOTE:")
    print("  The non-constant-time canonical form computation (Algorithm 22)")
    print("  leaks information via execution time. Blinding (Algorithm 24)")
    print("  is applied but relies on the monomial maps being uniform.")
    print("  If a GGM fault causes degenerate seeds (all-zero), the")
    print("  blinding monomials may lose uniformity → timing leak.")
    print()


# =====================================================================
#  Analysis 5: Practical Attack Cost Estimate
# =====================================================================

def attack_cost_estimate():
    """Estimate the practical cost of various fault attacks."""
    print("=" * 70)
    print("ANALYSIS 5: Attack Cost Estimates")
    print("=" * 70)
    print()

    from math import comb, log2, ceil

    # Challenge entropy
    challenge_entropy = log2(comb(T, W))
    print(f"Challenge string entropy: log2(C({T},{W})) ≈ {challenge_entropy:.1f} bits")
    print()

    # Attack 1: Brute-force challenge positions
    print("Attack A: Brute-force challenge positions")
    print(f"  Cost: C({T},{W}) ≈ 2^{challenge_entropy:.1f} — infeasible")
    print()

    # Attack 2: Post-commitment safe-error (per leaf)
    print("Attack B: Post-commitment safe-error (per-leaf)")
    print(f"  Queries: {T} signing operations (one fault per leaf)")
    print(f"  Each query: fault one leaf seed after commitments,")
    print(f"  observe verify → learn challenge[i]")
    print(f"  Total: {T} queries → full challenge recovery")
    print()

    # Attack 3: Binary search on subtrees
    queries_binary = ceil(W * log2(T / W)) + W
    print("Attack C: Binary search on GGM subtrees")
    print(f"  Queries: ~{queries_binary} (binary search + refinement)")
    print(f"  More efficient than per-leaf if tree depth is small")
    print()

    # Attack 4: DFA with many faulted signatures
    print("Attack D: DFA with correlated faulted signatures")
    print(f"  Collect O({S * T}) faulted signatures per key")
    print(f"  Analyze coset representative correlations to recover")
    print(f"  the secret monomial maps μ_1, ..., μ_{{s-1}}")
    print(f"  Cost depends on algebraic analysis — open research problem")
    print()


# =====================================================================
#  Main
# =====================================================================

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("Usage: python3 analyse_faults.py <fault_results.csv>")
        sys.exit(1)

    csv_path = sys.argv[1]
    rows = load_csv(csv_path)
    print(f"Loaded {len(rows)} fault injection results from {csv_path}\n")

    safe_error_analysis(rows)
    differential_analysis(rows)
    challenge_recovery_analysis(rows)
    topology_analysis(rows)
    attack_cost_estimate()


if __name__ == "__main__":
    main()
