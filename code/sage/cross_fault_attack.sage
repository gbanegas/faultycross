#!/usr/bin/env sage
# =============================================================================
# Toy simulation of the Correction Fault Attack on CROSS
# Jendral, Dubrova, Guo, Johansson (2025)
#
# This script implements a small-parameter toy version of:
#   - CROSS key generation and signing (R-SDP variant, simplified)
#   - Fault injection: faulting one entry of the parity-check matrix H
#   - Algorithm 4: the correction-based recovery of one entry of the secret e
#
# Simplifications vs. the real scheme:
#   - No GGM tree, no Merkle proof structure
#   - Hashes are simulated via Python's built-in hash()
#   - chall1 / chall2 are sampled directly (no CSPRNG derivation chain)
#   - Only the R-SDP variant is shown (not R-SDP(G))
#
# Paper reference:
#   https://eprint.iacr.org/2025/1885
# =============================================================================

import random
from hashlib import sha256

#  Toy Parameters 
# Real CROSS-R-SDP 1: p=127, z=7, n=127, k=76, t=157, w=82
# We use much smaller values so the recovery loop finishes instantly.

p   = 127   # Field prime
z   = 7     # Subgroup order  (E has z elements)
g_E = 2     # Generator: E = {2^i mod p | i in 0..z-1} = {1,2,4,8,16,32,64}
n   = 12    # Code length       (rows of e)
k   = 8     # Code dimension    (H is (n-k) x n = 4 x 12)
t   = 8     # Signature rounds
w   = 4     # Weight of chall2  (w rounds reveal the seed; t-w reveal y,v)

assert n > k and w < t
Fp = GF(p)

# Restricted set E ⊂ Fp*
E_vals = [power_mod(g_E, i, p) for i in range(z)]
print(f"E = {{ {', '.join(str(v) for v in E_vals)} }}")
print(f"Parameters: p={p}, z={z}, n={n}, k={k}, t={t}, w={w}")
print(f"H is ({n-k}) x {n};  recovery complexity ≈ {(n-k)*n*(p-1)*z} attempts")
print()

#  Helpers 

def rand_e_exp():
    """Sample a secret exponent vector ē ∈ {0,...,z-1}^n."""
    return [randint(0, z - 1) for _ in range(n)]

def exps_to_vec(exps):
    """Convert exponent vector ē to e = g^ē over Fp."""
    return vector(Fp, [E_vals[i] for i in exps])

def h(obj):
    """Stand-in cryptographic hash: SHA-256 of the string representation."""
    return sha256(str(obj).encode()).hexdigest()

def cmt(s_prime_vec, v_exp_list):
    """Commitment to a per-round syndrome and v-exponents."""
    return h((tuple(int(x) for x in s_prime_vec), tuple(v_exp_list)))

#  Key Generation (Algorithm 1) 

def keygen():
    """
    Returns (H, e, e_exp, s) where:
      H     : public parity-check matrix [V | I_{n-k}] over Fp
      e     : secret restricted vector in E^n
      e_exp : exponents such that e = g^e_exp
      s     : public syndrome s = e H^T
    """
    V = random_matrix(Fp, n - k, k)
    H = block_matrix([[V, identity_matrix(Fp, n - k)]])  # shape (n-k) x n

    e_exp = rand_e_exp()
    e     = exps_to_vec(e_exp)
    s     = e * H.T                                       # syndrome in Fp^{n-k}

    return H, e, e_exp, s

#  Signing (Algorithm 2, simplified) 

def sign(H, e, e_exp, s):
    """
    Returns the signature components needed by the attacker:
      rounds : list of per-round data (u', e', v, y, chall1, chall2, ...)
      cmt0   : list of per-round commitments cmt0[i] = H(s'[i] | v̄[i])
      digest : hash of all cmt0 (stands in for the full Merkle root)
    """
    rounds = []

    #  Per-round commit phase 
    for _ in range(t):
        u_prime_vec = vector(Fp, [Fp.random_element() for _ in range(n)])
        ep_exp      = rand_e_exp()
        e_prime     = exps_to_vec(ep_exp)

        # v̄[i] = ē - ē'[i]  (mod z);  v[i] = g^v̄[i]
        v_exp = [(e_exp[j] - ep_exp[j]) % z for j in range(n)]
        v     = exps_to_vec(v_exp)

        # u[i] = v[i] ⊙ u'[i]  (componentwise in Fp)
        u = vector(Fp, [v[j] * u_prime_vec[j] for j in range(n)])

        # s'[i] = u[i] H^T  (per-round syndrome, using the TRUE H)
        s_prime = u * H.T

        rounds.append({
            'u_prime': u_prime_vec,
            'e_prime': e_prime,
            'v_exp'  : v_exp,
            'v'      : v,
            'u'      : u,
            's_prime': s_prime,
        })

    #  Challenges 
    # chall1 ∈ (Fp*)^t
    chall1 = [Fp.random_element() for _ in range(t)]
    chall1 = [c if c != 0 else Fp(1) for c in chall1]

    # chall2 : weight-w binary vector (1 = reveal seed; 0 = reveal y, v̄)
    chall2 = [0] * t
    for i in random.sample(range(t), w):
        chall2[i] = 1

    #  Response phase 
    for i, r in enumerate(rounds):
        r['chall1'] = chall1[i]
        r['chall2'] = chall2[i]
        # y[i] = u'[i] + chall1[i] * e'[i]
        r['y'] = r['u_prime'] + chall1[i] * r['e_prime']

    #  Build digest (simulates the Merkle root over all cmt0[i]) 
    cmt0_list = [cmt(r['s_prime'], r['v_exp']) for r in rounds]
    digest    = h(tuple(cmt0_list))

    return rounds, cmt0_list, digest

#  Fault Injection 

def inject_fault(H, x1, x2, delta):
    """
    Returns H̃ = H + Δ where Δ has a single non-zero entry δ at (x1, x2).
    Δ is NOT known to the attacker; we just record it here to be able to
    recompute the faulty syndromes.
    """
    H_faulty = Matrix(Fp, H)
    H_faulty[x1, x2] = H_faulty[x1, x2] + Fp(delta)
    return H_faulty

# Faulty Signing 

def faulty_sign(rounds, H_faulty):
    """
    Using the SAME per-round randomness (same u[i], v̄[i]) but the FAULTED H̃,
    compute the faulty syndromes s̃'[i] = u[i] H̃^T and build a faulty digest.

    In the real attack the signer does not know H has been faulted; the
    resulting signature contains a digest that reflects the wrong syndromes.
    """
    cmt0_faulty = []
    for r in rounds:
        sp_faulty = r['u'] * H_faulty.T      # s̃'[i] = u[i] H̃^T
        r['s_prime_faulty'] = sp_faulty
        cmt0_faulty.append(cmt(sp_faulty, r['v_exp']))
    digest_faulty = h(tuple(cmt0_faulty))
    return cmt0_faulty, digest_faulty

#  Algorithm 4: Structure-Aware Correction Recovery 

def recover(H, s, rounds, chall2, cmt0_faulty, digest_faulty):
    """
    Implements Algorithm 4 from the paper (Theorem 1).

    Enumerates all candidates (x̂1, x̂2, δ̂, ê_val) and checks:

        s̃'[i] = (y[i] ⊙ v[i]) (H + Δ̂)^T  −  chall1[i] (s + ê Δ̂^T)

    for every revealed round (chall2[i] = 0).  The check is done by
    recomputing the per-round commitments and comparing the resulting digest
    to the faulty digest embedded in the signature.

    Returns (x2_found, e_val_found) or None if no candidate matched.
    """
    revealed = [i for i in range(t) if chall2[i] == 0]   # rounds where y,v̄ appear

    attempts = 0

    for x1 in range(n - k):            # row index in H (= column in H^T)
        for x2 in range(n):            # column index in H (= entry index in e)
            for delta_hat in range(1, p):      # δ̂ ∈ Fp \ {0}

                # Build Δ̂ (matrix with one non-zero entry)
                Delta_hat = zero_matrix(Fp, n - k, n)
                Delta_hat[x1, x2] = Fp(delta_hat)
                H_hat = H + Delta_hat

                for e_hat_val in E_vals:     # ê_{x2} ∈ E

                    attempts += 1

                    # ê is weight-1 with non-zero entry at position x2
                    e_hat = vector(Fp, [0] * n)
                    e_hat[x2] = Fp(e_hat_val)

                    # Modified syndrome: s + ê Δ̂^T
                    s_hat = s + e_hat * Delta_hat.T

                    # Re-derive cmt0 for revealed rounds; keep faulty values
                    # for unrevealed rounds (those come from the tree proof).
                    cmt0_check = list(cmt0_faulty)   # copy; unrevealed stay as-is

                    for i in revealed:
                        r = rounds[i]
                        # y'[i] = v[i] ⊙ y[i]
                        y_prime = vector(Fp, [r['v'][j] * r['y'][j] for j in range(n)])
                        # Equation (1): s'_check[i] = y'[i](H+Δ̂)^T − chall1[i](s+êΔ̂^T)
                        s_check = y_prime * H_hat.T - r['chall1'] * s_hat
                        cmt0_check[i] = cmt(s_check, r['v_exp'])

                    # Accept if the reconstructed digest matches the faulty signature
                    if h(tuple(cmt0_check)) == digest_faulty:
                        return x2, e_hat_val, attempts

    return None, None, attempts

#  Main 

print("=" * 62)
print("  CROSS Correction Fault Attack — Toy Simulation")
print("=" * 62)

# 1. Key generation
H, e, e_exp, s = keygen()
print("\n[1] Key Generation")
print(f"    Secret exponents ē : {e_exp}")
print(f"    Secret vector e    : {[int(x) for x in e]}")

# 2. Honest signing
rounds, cmt0_true, digest_true = sign(H, e, e_exp, s)
chall2 = [r['chall2'] for r in rounds]
revealed = [i for i in range(t) if chall2[i] == 0]
print(f"\n[2] Signing")
print(f"    chall2             : {chall2}")
print(f"    Revealed rounds    : {revealed}  ({len(revealed)} rounds, need y[i] and v̄[i])")

# 3. Fault injection (attacker does NOT know x1, x2, delta — chosen randomly)
fault_x1    = randint(0, n - k - 1)
fault_x2    = randint(0, n - 1)
fault_delta = randint(1, p - 1)
H_faulty    = inject_fault(H, fault_x1, fault_x2, fault_delta)

print(f"\n[3] Fault Injection  (attacker does NOT know these values)")
print(f"    True fault position : H[{fault_x1}, {fault_x2}]")
print(f"    True fault delta    : {fault_delta}")
print(f"    True e[{fault_x2}]           = {int(e[fault_x2])}")

# 4. Signing with faulted H
cmt0_faulty, digest_faulty = faulty_sign(rounds, H_faulty)
print(f"\n[4] Faulty Signature")
print(f"    Digest changed     : {digest_true != digest_faulty}")

# 5. Recovery (Algorithm 4)
print(f"\n[5] Running Recovery (Algorithm 4) ...")
x2_found, e_val_found, attempts = recover(H, s, rounds, chall2, cmt0_faulty, digest_faulty)

print(f"    Attempts made      : {attempts}")
if x2_found is not None:
    correct = (x2_found == fault_x2) and (int(e_val_found) == int(e[fault_x2]))
    print(f"    Recovered e[{x2_found}]    = {int(e_val_found)}")
    print(f"    True      e[{fault_x2}]    = {int(e[fault_x2])}")
    print(f"\n    SUCCESS : {correct}")
    if not correct:
        print("    (Spurious match — try re-running; negligible probability per Theorem 1)")
else:
    print("    No candidate matched — unexpected (check parameters).")

#  Sanity checks 

print("\n[Sanity checks]")
# The true syndrome equation s = e H^T must hold
assert e * H.T == s,            "Syndrome check failed"
# Honest digest must differ from faulty digest
assert digest_true != digest_faulty, "Fault had no effect on digest"
# The non-zero column of Δ affects rows in H^T indexed by x1
Delta = zero_matrix(Fp, n - k, n)
Delta[fault_x1, fault_x2] = Fp(fault_delta)
diff = e * Delta.T
print(f"    e · Δ^T = {[int(x) for x in diff]}  (only entry {fault_x1} non-zero: {int(diff[fault_x1])})")
print("    All checks passed.")
