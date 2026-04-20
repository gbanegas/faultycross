/**
 * Post-Commitment Safe-Error Attack on LESS BuildGGM (Corrected)
 * ===============================================================
 *
 * ATTACK MODEL: An attacker can physically fault one node in the
 * GGM tree during a signing operation, AFTER the commitment hash
 * is computed but BEFORE GGMPath. The attacker observes whether
 * the output signature verifies.
 *
 * KEY INSIGHT: Each signing uses fresh randomness (salt + ephemeral
 * seeds), so each signing has a DIFFERENT challenge. The attacker
 * can fault only ONE node per signing. But across many signings,
 * the attacker accumulates challenge-position information.
 *
 * This program simulates:
 *  1. Single-signing analysis: for ONE signing, show which nodes
 *     would be safe-errors (all descendants withheld)
 *  2. Multi-signing attack: across many signings, each with one
 *     fault, statistically recover challenge positions
 *
 * Build: cmake .. -DCMAKE_BUILD_TYPE=Release && make LESS_post_commit_v2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "LESS.h"
#include "api.h"
#include "rng.h"
#include "seedtree.h"
#include "parameters.h"
#include "utils.h"
#include "canonical.h"
#include "fips202.h"
#include "sha3.h"
#include "monomial_mat.h"
#include "codes.h"

#define LEFT_CHILD(i) (2*(i)+1)

/* ------------------------------------------------------------------ */
/*  Tree utilities                                                    */
/* ------------------------------------------------------------------ */

static void get_descendant_leaves(int node, int *leaves, int *count)
{
    const uint16_t off[LOG2(T)+1]  = TREE_OFFSETS;
    const uint16_t npl[LOG2(T)+1]  = TREE_NODES_PER_LEVEL;
    const uint16_t cons_leaves[TREE_SUBROOTS]          = TREE_CONSECUTIVE_LEAVES;
    const uint16_t leaves_start_indices[TREE_SUBROOTS]  = TREE_LEAVES_START_INDICES;

    int active[NUM_NODES_SEED_TREE];
    memset(active, 0, sizeof(active));
    active[node] = 1;
    *count = 0;

    int start = 0;
    for (int level = 0; level <= LOG2(T); level++) {
        for (int i = 0; i < npl[level]; i++) {
            int nd = start + i;
            if (!active[nd]) continue;
            int running = 0;
            for (int s = 0; s < TREE_SUBROOTS; s++) {
                for (int j = 0; j < (int)cons_leaves[s]; j++) {
                    if ((int)(leaves_start_indices[s] + j) == nd) {
                        leaves[(*count)++] = running + j;
                        goto next_nd;
                    }
                }
                running += cons_leaves[s];
            }
            if (level < LOG2(T)) {
                int lc = LEFT_CHILD(nd) - off[level];
                if (lc < NUM_NODES_SEED_TREE)     active[lc] = 1;
                if (lc + 1 < NUM_NODES_SEED_TREE) active[lc + 1] = 1;
            }
            next_nd:;
        }
        start += npl[level];
    }
}

static int get_node_level(int node)
{
    const uint16_t npl[LOG2(T)+1] = TREE_NODES_PER_LEVEL;
    int start = 0;
    for (int level = 0; level <= LOG2(T); level++) {
        if (node >= start && node < start + npl[level]) return level;
        start += npl[level];
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Sign and return the challenge (no fault, just for analysis)       */
/* ------------------------------------------------------------------ */

static size_t sign_and_get_challenge(
    const prikey_t *SK, const pubkey_t *PK,
    const char *msg, uint64_t mlen,
    sign_t *sig, uint8_t challenge[T])
{
    size_t ns = LESS_sign(SK, msg, mlen, sig);
    SampleChallenge(challenge, sig->digest);
    return ns;
}

/* ------------------------------------------------------------------ */
/*  Sign with a post-commitment fault and check verification          */
/*  Returns: 1 if verify passes (safe error), 0 if fails             */
/* ------------------------------------------------------------------ */

static int sign_with_post_commit_fault(
    const prikey_t *SK, const pubkey_t *PK,
    const char *msg, uint64_t mlen,
    int fault_node,
    uint8_t out_challenge[T])
{
    uint8_t g0_initial_pivot_flags[N_pad];
    uint8_t is_pivot_column[N_pad];

    SHAKE_STATE_STRUCT sk_shake_state;
    initialize_csprng(&sk_shake_state, SK->compressed_sk,
                      PRIVATE_KEY_SEED_LENGTH_BYTES);

    unsigned char G_0_seed[SEED_LENGTH_BYTES];
    csprng_randombytes(G_0_seed, SEED_LENGTH_BYTES, &sk_shake_state);

    unsigned char priv_seeds[NUM_KEYPAIRS-1][PRIVATE_KEY_SEED_LENGTH_BYTES];
    for (uint32_t i = 0; i < NUM_KEYPAIRS - 1; i++)
        csprng_randombytes(priv_seeds[i], PRIVATE_KEY_SEED_LENGTH_BYTES,
                           &sk_shake_state);

    sign_t sig;
    memset(&sig, 0, sizeof(sig));
    randombytes(sig.salt, HASH_DIGEST_LENGTH);

    unsigned char eseed[SEED_LENGTH_BYTES];
    csprng_randombytes(eseed, SEED_LENGTH_BYTES, &sk_shake_state);

    uint8_t cf_seed[SEED_LENGTH_BYTES];
    csprng_randombytes(cf_seed, SEED_LENGTH_BYTES, &sk_shake_state);
    SHAKE_STATE_STRUCT cf_shake;
    initialize_csprng(&cf_shake, cf_seed, SEED_LENGTH_BYTES);

    /* Build tree normally */
    unsigned char seed_tree[NUM_NODES_SEED_TREE * SEED_LENGTH_BYTES];
    memset(seed_tree, 0, sizeof(seed_tree));
    BuildGGM(seed_tree, eseed, sig.salt);

    unsigned char round_seeds[T * SEED_LENGTH_BYTES];
    memset(round_seeds, 0, sizeof(round_seeds));
    seed_leaves(round_seeds, seed_tree);

    /* Compute commitments normally */
    rref_generator_mat_t G0r;
    generator_sample(&G0r, G_0_seed);
    generator_get_pivot_flags(&G0r, g0_initial_pivot_flags);
    generator_mat_t full_G0, G0;
    generator_rref_expand(&full_G0, &G0r);

    monomial_t mu;
    monomial_action_IS_t pi_tilde[T];
    normalized_IS_t Ai = {0};

    LESS_SHA3_INC_CTX state;
    LESS_SHA3_INC_INIT(&state);

    for (uint32_t i = 0; i < T; i++) {
        monomial_sample_salt(&mu, round_seeds + i * SEED_LENGTH_BYTES,
                             sig.salt, i);
        generator_monomial_mul(&G0, &full_G0, &mu);
        memset(is_pivot_column, 0, N_pad);
#if defined(LESS_REUSE_PIVOTS_SG)
        uint8_t ppf[N_pad];
        for (uint32_t t = 0; t < N; t++)
            ppf[mu.permutation[t]] = g0_initial_pivot_flags[t];
        if (generator_RREF_pivot_reuse(&G0, is_pivot_column, ppf,
                                        SIGN_PIVOT_REUSE_LIMIT) == 0)
            return -1;
#else
        if (generator_RREF(&G0, is_pivot_column) == 0) return -1;
#endif
        uint32_t ctr = 0;
        for (uint32_t j = 0; j < N-K; j++) {
            while (is_pivot_column[ctr]) ctr++;
            for (uint32_t k = 0; k < K; k++)
                Ai.values[k][j] = G0.values[k][ctr];
            ctr++;
        }
        POSITION_T piv_idx = 0;
        for (uint32_t ci = 0; ci < N; ci++) {
            POSITION_T ri = 0;
            for (uint32_t t = 0; t < N; t++)
                if (mu.permutation[t] == ci) { ri = t; break; }
            if (is_pivot_column[ci] == 1)
                pi_tilde[i].permutation[piv_idx++] = ri;
        }
        blind(&Ai, &cf_shake);
        int cf_ok = CF(&Ai);
        if (cf_ok == 0) {
            *(round_seeds + i * SEED_LENGTH_BYTES) += 1;
            i--; continue;
        }
#if defined(USE_AVX2) || defined(USE_NEON)
        for (uint32_t sl = 0; sl < K; sl++)
            LESS_SHA3_INC_ABSORB(&state, Ai.values[sl], K);
#else
        LESS_SHA3_INC_ABSORB(&state, (uint8_t *)&Ai, sizeof(normalized_IS_t));
#endif
    }

    LESS_SHA3_INC_ABSORB(&state, (const uint8_t *)msg, mlen);
    LESS_SHA3_INC_ABSORB(&state, sig.salt, HASH_DIGEST_LENGTH);
    LESS_SHA3_INC_FINALIZE(sig.digest, &state);

    /* Challenge is now FIXED */
    uint8_t fws[T] = {0};
    SampleChallenge(fws, sig.digest);
    memcpy(out_challenge, fws, T);

    uint8_t itp[T];
    for (uint32_t i = 0; i < T; i++) itp[i] = !!(fws[i]);

    /* ╔══════════════════════════════════════════╗
     * ║  FAULT: corrupt seed_tree at fault_node  ║
     * ╚══════════════════════════════════════════╝ */
    if (fault_node >= 0 && fault_node < NUM_NODES_SEED_TREE)
        seed_tree[fault_node * SEED_LENGTH_BYTES] ^= 0xFF;

    /* GGMPath on (possibly corrupted) tree */
    memset(&sig.seed_storage, 0, SEED_TREE_MAX_PUBLISHED_BYTES);
    uint32_t nsp = GGMPath(seed_tree, itp, (unsigned char *)&sig.seed_storage);

    int em = 0;
    monomial_action_IS_t ma;
    for (uint32_t i = 0; i < T; i++) {
        if (fws[i] != 0) {
            monomial_t Qtmp;
            monomial_sample_prikey(&Qtmp, priv_seeds[fws[i]-1]);
            monomial_compose_action(&ma, &Qtmp, &pi_tilde[i]);
            CosetRep(sig.cf_monom_actions[em++], &ma);
        }
    }
    (void)nsp;

    /* Verify */
    return LESS_verify(PK, msg, mlen, &sig);
}

/* ------------------------------------------------------------------ */
/*  Analysis 1: Single-signing oracle map                             */
/* ------------------------------------------------------------------ */

static void single_signing_analysis(const prikey_t *sk, const pubkey_t *pk)
{
    printf("============================================================\n");
    printf("  Single-Signing Safe-Error Oracle Map\n");
    printf("============================================================\n\n");

    /* Do one signing to get the challenge */
    const char *msg = "single signing analysis";
    uint64_t mlen = strlen(msg);
    sign_t sig;
    uint8_t challenge[T];
    sign_and_get_challenge(sk, pk, msg, mlen, &sig, challenge);

    int w_count = 0;
    for (int i = 0; i < T; i++) if (challenge[i]) w_count++;
    printf("Challenge: w=%d withheld positions out of T=%d\n", w_count, T);
    printf("Challenge: ");
    for (int i = 0; i < T; i++) printf("%d", challenge[i] ? 1 : 0);
    printf("\n\n");

    /* For each node, check if ALL descendant leaves are withheld */
    printf("node,level,desc_leaves,desc_published,desc_withheld,"
           "is_safe_error\n");

    int safe_error_count = 0;
    int safe_error_bits = 0;  /* leaves learnable from safe errors */

    for (int node = 0; node < NUM_NODES_SEED_TREE; node++) {
        int desc[T], n_desc = 0;
        get_descendant_leaves(node, desc, &n_desc);
        if (n_desc == 0) continue;

        int pub = 0, wth = 0;
        for (int d = 0; d < n_desc; d++) {
            if (challenge[desc[d]] == 0) pub++;
            else wth++;
        }

        int safe = (pub == 0);
        printf("%d,%d,%d,%d,%d,%d\n",
               node, get_node_level(node), n_desc, pub, wth, safe);

        if (safe) {
            safe_error_count++;
            safe_error_bits += n_desc;
        }
    }

    printf("\nSafe-error nodes (fault would be invisible): %d\n",
           safe_error_count);
    printf("Total leaf positions learnable from safe errors: %d / %d\n",
           safe_error_bits, T);
    printf("(Each safe-error node tells you its descendants are all withheld)\n\n");

    /* Identify the optimal faulting strategy */
    printf("Optimal single-fault strategy:\n");
    printf("  Fault the ROOT (node 0): all %d descendants\n", T);
    printf("    If PASS: impossible (root has published descendants)\n");
    printf("    If FAIL: learn nothing new\n\n");

    /* Find the highest-level safe-error nodes (most information per fault) */
    printf("Highest-level safe-error nodes (most info per query):\n");
    for (int node = 0; node < NUM_NODES_SEED_TREE; node++) {
        int desc[T], n_desc = 0;
        get_descendant_leaves(node, desc, &n_desc);
        if (n_desc < 2) continue;  /* skip single-leaf nodes */

        int pub = 0;
        for (int d = 0; d < n_desc; d++)
            if (challenge[desc[d]] == 0) pub++;

        if (pub == 0) {
            printf("  node %3d (level %d): %d withheld leaves in subtree\n",
                   node, get_node_level(node), n_desc);
        }
    }
    printf("\n");
}

/* ------------------------------------------------------------------ */
/*  Analysis 2: Multi-signing statistical attack                      */
/* ------------------------------------------------------------------ */

static void multi_signing_attack(const prikey_t *sk, const pubkey_t *pk,
                                 int num_signings, int target_node)
{
    printf("============================================================\n");
    printf("  Multi-Signing Statistical Attack\n");
    printf("  Target node: %d (level %d)\n", target_node,
           get_node_level(target_node));
    printf("  Signings: %d\n", num_signings);
    printf("============================================================\n\n");

    const char *msg = "multi-signing fault analysis";
    uint64_t mlen = strlen(msg);

    int desc[T], n_desc = 0;
    get_descendant_leaves(target_node, desc, &n_desc);
    printf("Node %d has %d descendant leaves\n\n", target_node, n_desc);

    /* For each leaf, count how often it appears in a "safe error" signing */
    int safe_count = 0;
    int fail_count = 0;

    /* Track which leaves are withheld across safe-error signings */
    int always_withheld[T];
    memset(always_withheld, 0, sizeof(always_withheld));

    printf("signing,verify_result,challenge_weight\n");

    for (int s = 0; s < num_signings; s++) {
        uint8_t challenge[T];
        int ok = sign_with_post_commit_fault(sk, pk, msg, mlen,
                                              target_node, challenge);

        int w = 0;
        for (int i = 0; i < T; i++) if (challenge[i]) w++;

        printf("%d,%d,%d\n", s, ok, w);

        if (ok) {
            /* Safe error: all descendant leaves are withheld */
            safe_count++;
            for (int d = 0; d < n_desc; d++)
                always_withheld[desc[d]]++;
        } else {
            fail_count++;
        }
    }

    printf("\n");
    printf("Results:\n");
    printf("  Safe errors (PASS): %d / %d (%.1f%%)\n",
           safe_count, num_signings, 100.0 * safe_count / num_signings);
    printf("  Failures (FAIL):    %d / %d (%.1f%%)\n",
           fail_count, num_signings, 100.0 * fail_count / num_signings);

    /* Expected safe-error probability:
     * P(safe) = C(T - n_desc, W) / C(T, W)
     * = probability that all W withheld positions avoid the n_desc descendants */
    double p_safe = 1.0;
    for (int i = 0; i < n_desc; i++)
        p_safe *= (double)(T - W - i) / (T - i);

    printf("\n  Expected P(safe error) = %.4f  (%.1f%%)\n",
           p_safe, 100.0 * p_safe);
    printf("  Observed P(safe error) = %.4f  (%.1f%%)\n",
           (double)safe_count / num_signings,
           100.0 * safe_count / num_signings);

    printf("\n  INFORMATION LEAKED PER SAFE-ERROR OBSERVATION:\n");
    printf("  When verify PASSES for node %d, the attacker learns:\n",
           target_node);
    printf("    \"All %d descendant leaves (rounds ", n_desc);
    for (int d = 0; d < n_desc && d < 5; d++) printf("%d,", desc[d]);
    if (n_desc > 5) printf("...");
    printf(") have challenge ≠ 0\"\n");
    printf("  This eliminates %d positions from the published set.\n\n",
           n_desc);
}

/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    fprintf(stderr, "=== LESS-252-192 Post-Commitment Attack (v2) ===\n");
    fprintf(stderr, "n=%d k=%d q=%d t=%d w=%d s=%d\n\n", N, K, Q, T, W, NUM_KEYPAIRS);

    unsigned char pseed[32];
    for (int i = 0; i < 32; i++) pseed[i] = (unsigned char)(0x42 + i);
    initialize_csprng(&platform_csprng_state, pseed, 32);

    prikey_t sk;
    pubkey_t pk;
    LESS_keygen(&sk, &pk);

    /* Analysis 1: single-signing oracle map */
    single_signing_analysis(&sk, &pk);

    /* Analysis 2: multi-signing attack on a specific node */
    int target = 7;  /* level-3 node, ~32 descendant leaves */
    int n_signings = 20;

    if (argc >= 2) target = atoi(argv[1]);
    if (argc >= 3) n_signings = atoi(argv[2]);

    multi_signing_attack(&sk, &pk, n_signings, target);

    /* Summary */
    printf("============================================================\n");
    printf("  ATTACK SUMMARY\n");
    printf("============================================================\n\n");
    printf("The post-commitment safe-error attack works as follows:\n\n");
    printf("1. The attacker faults node X in the GGM tree after the\n");
    printf("   commitment hash is finalized but before GGMPath.\n\n");
    printf("2. If verification PASSES:\n");
    printf("   → All descendant leaves of X have challenge ≠ 0\n");
    printf("   → The attacker learns %d-%d positions are withheld\n\n",
           1, T/2);
    printf("3. If verification FAILS:\n");
    printf("   → At least one descendant has challenge = 0\n\n");
    printf("4. Each signing query leaks information about ONE\n");
    printf("   challenge string. The challenge is fresh each time\n");
    printf("   (random salt), but the SECRET KEY is the same.\n\n");
    printf("5. Over many signings, the attacker collects:\n");
    printf("   - Challenge positions (from safe-error oracle)\n");
    printf("   - Coset representatives (from the signature)\n");
    printf("   Both are tied to the SAME secret monomial maps.\n\n");
    printf("6. Statistical analysis of these pairs can reconstruct\n");
    printf("   the secret key. The exact algebraic attack depends\n");
    printf("   on exploiting the structure of CosetRep.\n\n");
    printf("PRACTICAL REQUIREMENTS:\n");
    printf("  - Precise fault timing (after Hash, before GGMPath)\n");
    printf("  - ~%d signings for statistical significance\n",
           (int)(T / (W * 1.0 / T) + 0.5));
    printf("  - Physical access to the signing device\n");

    return 0;
}
