/**
 * Debug harness: log which nodes GGMPath actually emits for a clean signing,
 * and verify that fault at each emitted node FAILs while fault at each
 * non-emitted node PASSes. This lets us validate the oracle contract
 * independently from the binary-search algorithm.
 *
 * Run: ./LESS_oracle_debug
 * Expected: "Oracle contract holds: N FAIL for N emitted nodes, M PASS for
 * M non-emitted nodes."
 *
 * If the output shows FAILs at non-emitted nodes or PASSes at emitted
 * nodes, we have a seed_tree aliasing bug; read the detailed per-node
 * log and look for index collisions.
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

#define TO_PUBLISH     0
#define NOT_TO_PUBLISH 1

/* --------------------------------------------------------------- */
/*  LESS_sign with a fault and, optionally, a logging side-channel */
/*  that writes which linearized node indices GGMPath emits.       */
/* --------------------------------------------------------------- */

/* We replicate GGMPath but also record emitted node indices in out_E[]. */
static uint32_t GGMPath_traced(
    const unsigned char seed_tree[NUM_NODES_SEED_TREE*SEED_LENGTH_BYTES],
    const unsigned char indices_to_publish[T],
    unsigned char *seed_storage,
    int out_E[NUM_NODES_SEED_TREE])
{
    unsigned char flags_tree[NUM_NODES_SEED_TREE];
    memset(flags_tree, NOT_TO_PUBLISH, sizeof(flags_tree));

    /* label_leaves */
    const uint16_t cons_leaves[TREE_SUBROOTS]          = TREE_CONSECUTIVE_LEAVES;
    const uint16_t leaves_start_indices[TREE_SUBROOTS]  = TREE_LEAVES_START_INDICES;
    unsigned int cnt = 0;
    for (size_t i = 0; i < TREE_SUBROOTS; i++)
        for (size_t j = 0; j < cons_leaves[i]; j++)
            flags_tree[leaves_start_indices[i] + j] = indices_to_publish[cnt++];

    /* compute_seeds_to_publish propagation */
    const uint16_t off[LOG2(T)+1] = TREE_OFFSETS;
    const uint16_t npl[LOG2(T)+1] = TREE_NODES_PER_LEVEL;
    unsigned int start_node = leaves_start_indices[0];
    for (int level = LOG2(T); level > 0; level--) {
        for (int i = npl[level] - 2; i >= 0; i -= 2) {
            uint16_t current = start_node + i;
            uint16_t parent  = ((current - 1) / 2) + (off[level-1] >> 1);
            uint16_t sibling = (current % 2) ? current + 1 : current - 1;
            if (flags_tree[current] == TO_PUBLISH && flags_tree[sibling] == TO_PUBLISH)
                flags_tree[parent] = TO_PUBLISH;
            else
                flags_tree[parent] = NOT_TO_PUBLISH;
        }
        start_node -= npl[level-1];
    }

    /* Emit */
    int nE = 0;
    int num_seeds_published = 0;
    int start = 1;
    for (int level = 1; level <= LOG2(T); level++) {
        for (int i = 0; i < npl[level]; i++) {
            uint16_t current = start + i;
            uint16_t parent  = ((current - 1) / 2) + (off[level-1] >> 1);
            if (flags_tree[current] == TO_PUBLISH &&
                flags_tree[parent]  == NOT_TO_PUBLISH) {
                memcpy(seed_storage + num_seeds_published*SEED_LENGTH_BYTES,
                       seed_tree + current*SEED_LENGTH_BYTES,
                       SEED_LENGTH_BYTES);
                out_E[nE++] = current;
                num_seeds_published++;
            }
        }
        start += npl[level];
    }
    return num_seeds_published;
}

/* --------------------------------------------------------------- */
/*  Sign with optional fault and optional E tracing                */
/* --------------------------------------------------------------- */

static size_t sign_with_fault_and_trace(
    const prikey_t *SK, const char *m, uint64_t mlen,
    sign_t *sig,
    int fault_node,           /* -1 = no fault */
    int out_E[NUM_NODES_SEED_TREE], int *out_E_count,
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

    randombytes(sig->salt, HASH_DIGEST_LENGTH);

    unsigned char eseed[SEED_LENGTH_BYTES];
    csprng_randombytes(eseed, SEED_LENGTH_BYTES, &sk_shake_state);

    uint8_t cf_seed[SEED_LENGTH_BYTES];
    csprng_randombytes(cf_seed, SEED_LENGTH_BYTES, &sk_shake_state);
    SHAKE_STATE_STRUCT cf_shake;
    initialize_csprng(&cf_shake, cf_seed, SEED_LENGTH_BYTES);

    unsigned char seed_tree[NUM_NODES_SEED_TREE * SEED_LENGTH_BYTES];
    memset(seed_tree, 0, sizeof(seed_tree));
    BuildGGM(seed_tree, eseed, sig->salt);

    unsigned char round_seeds[T * SEED_LENGTH_BYTES];
    memset(round_seeds, 0, sizeof(round_seeds));
    seed_leaves(round_seeds, seed_tree);

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
                             sig->salt, i);
        generator_monomial_mul(&G0, &full_G0, &mu);
        memset(is_pivot_column, 0, N_pad);
#if defined(LESS_REUSE_PIVOTS_SG)
        uint8_t ppf[N_pad];
        for (uint32_t t = 0; t < N; t++)
            ppf[mu.permutation[t]] = g0_initial_pivot_flags[t];
        if (generator_RREF_pivot_reuse(&G0, is_pivot_column, ppf,
                                        SIGN_PIVOT_REUSE_LIMIT) == 0) return 0;
#else
        if (generator_RREF(&G0, is_pivot_column) == 0) return 0;
#endif
        uint32_t ctr = 0;
        for (uint32_t j = 0; j < N - K; j++) {
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

    LESS_SHA3_INC_ABSORB(&state, (const uint8_t *)m, mlen);
    LESS_SHA3_INC_ABSORB(&state, sig->salt, HASH_DIGEST_LENGTH);
    LESS_SHA3_INC_FINALIZE(sig->digest, &state);

    uint8_t fws[T] = {0};
    SampleChallenge(fws, sig->digest);
    memcpy(out_challenge, fws, T);

    uint8_t itp[T];
    for (uint32_t i = 0; i < T; i++) itp[i] = !!(fws[i]);

    /* ─── fault point ─── */
    if (fault_node >= 0 && fault_node < NUM_NODES_SEED_TREE)
        seed_tree[fault_node * SEED_LENGTH_BYTES] ^= 0xFF;

    memset(&sig->seed_storage, 0, SEED_TREE_MAX_PUBLISHED_BYTES);

    /* Traced version if out_E != NULL, otherwise call the real GGMPath */
    uint32_t nsp;
    if (out_E != NULL) {
        nsp = GGMPath_traced(seed_tree, itp, (unsigned char *)&sig->seed_storage, out_E);
        *out_E_count = (int)nsp;
    } else {
        nsp = GGMPath(seed_tree, itp, (unsigned char *)&sig->seed_storage);
    }

    int em = 0;
    monomial_action_IS_t ma;
    for (uint32_t i = 0; i < T; i++) {
        if (fws[i] != 0) {
            monomial_t Qtmp;
            monomial_sample_prikey(&Qtmp, priv_seeds[fws[i]-1]);
            monomial_compose_action(&ma, &Qtmp, &pi_tilde[i]);
            CosetRep(sig->cf_monom_actions[em++], &ma);
        }
    }
    return nsp;
}

/* --------------------------------------------------------------- */
int main(void)
{
    fprintf(stderr, "=== LESS-252-192 Oracle Contract Validator ===\n");
    fprintf(stderr, "n=%d k=%d q=%d t=%d w=%d\n\n", N, K, Q, T, W);

    unsigned char pseed[32];
    for (int i = 0; i < 32; i++) pseed[i] = (unsigned char)(0x42 + i);
    initialize_csprng(&platform_csprng_state, pseed, 32);

    prikey_t sk; pubkey_t pk;
    LESS_keygen(&sk, &pk);

    const char *msg = "LESS oracle debug";
    uint64_t mlen = strlen(msg);

    /* Step 1: do ONE clean signing to learn the ground-truth E for it. */
    sign_t ref_sig;
    memset(&ref_sig, 0, sizeof(ref_sig));
    uint8_t ref_challenge[T];
    int ref_E[NUM_NODES_SEED_TREE];
    int ref_E_count = 0;

    size_t ref_nsp = sign_with_fault_and_trace(&sk, msg, mlen, &ref_sig,
                                                -1, ref_E, &ref_E_count,
                                                ref_challenge);
    (void)ref_nsp;

    printf("Ground-truth emitted set E (|E| = %d):\n  ", ref_E_count);
    for (int k = 0; k < ref_E_count; k++) printf("%d ", ref_E[k]);
    printf("\n\n");

    /* NOTE: next sign call will pick a DIFFERENT fresh salt, so its E
     * will be different. We cannot validate the oracle against ref_E
     * unless we also fix the salt. So instead: for each node, run a
     * fresh signing with a fault at that node, re-derive E for THAT
     * signing, check whether (verify_fail) == (fault_node ∈ E_that).
     *
     * This is the correct per-query contract test. */

    int fails_when_in_E = 0, fails_when_not_in_E = 0;
    int passes_when_in_E = 0, passes_when_not_in_E = 0;
    int total_tested = 0;

    /* To keep the debug run short, sample 40 nodes spread across levels. */
    int nodes_to_test[] = {
        1, 2,                           /* subroots */
        3, 4, 5, 6,                     /* level 2 */
        39, 54, 94, 95,                 /* interior level 5-6 */
        191, 192, 200, 224,             /* level 7 leaves/internal */
        255, 256, 281, 327, 382         /* level 8 */
    };
    int n_test = sizeof(nodes_to_test) / sizeof(nodes_to_test[0]);

    for (int t = 0; t < n_test; t++) {
        int target = nodes_to_test[t];

        sign_t sig;
        memset(&sig, 0, sizeof(sig));
        uint8_t ch[T];
        int E_this[NUM_NODES_SEED_TREE];
        int E_this_count = 0;

        sign_with_fault_and_trace(&sk, msg, mlen, &sig, target,
                                   E_this, &E_this_count, ch);
        int verify_ok = LESS_verify(&pk, msg, mlen, &sig);

        int in_E = 0;
        for (int k = 0; k < E_this_count; k++)
            if (E_this[k] == target) { in_E = 1; break; }

        const char *expected = in_E ? "FAIL" : "PASS";
        const char *actual   = verify_ok ? "PASS" : "FAIL";
        const char *match    = (in_E == !verify_ok) ? "OK" : "MISMATCH";

        printf("node %3d : in_E=%d  expected=%s  actual=%s  [%s]\n",
               target, in_E, expected, actual, match);

        if (in_E && !verify_ok)  fails_when_in_E++;
        if (in_E &&  verify_ok)  passes_when_in_E++;
        if (!in_E && !verify_ok) fails_when_not_in_E++;
        if (!in_E &&  verify_ok) passes_when_not_in_E++;
        total_tested++;
    }

    printf("\n================================================\n");
    printf("  Oracle Contract Validation\n");
    printf("================================================\n");
    printf("Nodes tested                : %d\n", total_tested);
    printf("FAIL where in E  (expected) : %d\n", fails_when_in_E);
    printf("PASS where in E  (BUG)      : %d  <-- if >0, oracle broken\n", passes_when_in_E);
    printf("FAIL where NOT E (BUG)      : %d  <-- if >0, oracle broken\n", fails_when_not_in_E);
    printf("PASS where NOT E (expected) : %d\n", passes_when_not_in_E);

    if (passes_when_in_E == 0 && fails_when_not_in_E == 0)
        printf("\n★ Oracle contract holds. ★\n");
    else
        printf("\n!! Oracle contract VIOLATED. Investigate mismatched nodes above.\n");

    return 0;
}
