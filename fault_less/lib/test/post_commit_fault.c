/**
 * Post-Commitment Safe-Error Attack on LESS BuildGGM
 * ===================================================
 *
 * This implements the most powerful fault model: corrupting the seed_tree
 * AFTER the commitment hash is computed but BEFORE GGMPath extracts the
 * published seeds. Since the challenge is already fixed, the fault creates
 * a direct safe-error oracle:
 *
 *   - Fault at node X → verify PASSES  ⟹  all descendants of X are
 *     withheld (challenge ≠ 0) → LEAK challenge positions
 *
 *   - Fault at node X → verify FAILS   ⟹  at least one descendant of X
 *     is published (challenge = 0)
 *
 * With O(T) = 192 such queries, the full challenge string is recovered,
 * which has ~130 bits of entropy. Combined with the coset representatives,
 * this enables key recovery.
 *
 * Build: cmake .. && make LESS_post_commit_fault
 *   (with -DCATEGORY=252 -DTARGET=192)
 *
 * Usage: ./LESS_post_commit_fault [leaf|node|binary_search]
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

/* ------------------------------------------------------------------ */
/*  LESS_sign with post-commitment fault injection point              */
/* ------------------------------------------------------------------ */

/**
 * Sign with a fault injected AFTER the commitment hash, BEFORE GGMPath.
 *
 * @param fault_node   linearized tree node to corrupt (-1 = no fault)
 * @param out_challenge  filled with the challenge string (T bytes)
 *
 * The fault XORs byte 0 of the target node's seed with 0xFF.
 */
static size_t LESS_sign_post_commit_fault(
    const prikey_t *SK,
    const char *const m,
    const uint64_t mlen,
    sign_t *sig,
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

    unsigned char private_monomial_seeds[NUM_KEYPAIRS - 1][PRIVATE_KEY_SEED_LENGTH_BYTES];
    for (uint32_t i = 0; i < NUM_KEYPAIRS - 1; i++)
        csprng_randombytes(private_monomial_seeds[i],
                           PRIVATE_KEY_SEED_LENGTH_BYTES, &sk_shake_state);

    randombytes(sig->salt, HASH_DIGEST_LENGTH);

    unsigned char ephem_monomials_seed[SEED_LENGTH_BYTES];
    csprng_randombytes(ephem_monomials_seed, SEED_LENGTH_BYTES, &sk_shake_state);

    uint8_t cf_seed[SEED_LENGTH_BYTES];
    csprng_randombytes(cf_seed, SEED_LENGTH_BYTES, &sk_shake_state);
    SHAKE_STATE_STRUCT cf_shake_state;
    initialize_csprng(&cf_shake_state, cf_seed, SEED_LENGTH_BYTES);

    /* ── Step 1: Build the GGM tree (no fault yet) ── */
    unsigned char seed_tree[NUM_NODES_SEED_TREE * SEED_LENGTH_BYTES];
    memset(seed_tree, 0, sizeof(seed_tree));
    BuildGGM(seed_tree, ephem_monomials_seed, sig->salt);

    unsigned char linearized_rounds_seeds[T * SEED_LENGTH_BYTES];
    memset(linearized_rounds_seeds, 0, sizeof(linearized_rounds_seeds));
    seed_leaves(linearized_rounds_seeds, seed_tree);

    /* ── Step 2: Compute commitments (fault-free) ── */
    rref_generator_mat_t G0_rref;
    generator_sample(&G0_rref, G_0_seed);
    generator_get_pivot_flags(&G0_rref, g0_initial_pivot_flags);
    generator_mat_t full_G0, G0;
    generator_rref_expand(&full_G0, &G0_rref);

    monomial_t mu_tilde;
    monomial_action_IS_t pi_tilde[T];
    normalized_IS_t A_i = {0};

    LESS_SHA3_INC_CTX state;
    LESS_SHA3_INC_INIT(&state);

    for (uint32_t i = 0; i < T; i++) {
        monomial_sample_salt(&mu_tilde,
                             linearized_rounds_seeds + i * SEED_LENGTH_BYTES,
                             sig->salt, i);
        generator_monomial_mul(&G0, &full_G0, &mu_tilde);
        memset(is_pivot_column, 0, N_pad);
#if defined(LESS_REUSE_PIVOTS_SG)
        uint8_t ppf[N_pad];
        for (uint32_t t = 0; t < N; t++)
            ppf[mu_tilde.permutation[t]] = g0_initial_pivot_flags[t];
        if (generator_RREF_pivot_reuse(&G0, is_pivot_column, ppf,
                                        SIGN_PIVOT_REUSE_LIMIT) == 0)
            return 0;
#else
        if (generator_RREF(&G0, is_pivot_column) == 0) return 0;
#endif
        uint32_t ctr = 0;
        for (uint32_t j = 0; j < N - K; j++) {
            while (is_pivot_column[ctr]) ctr++;
            for (uint32_t k = 0; k < K; k++)
                A_i.values[k][j] = G0.values[k][ctr];
            ctr++;
        }
        POSITION_T piv_idx = 0;
        for (uint32_t col_idx = 0; col_idx < N; col_idx++) {
            POSITION_T row_idx = 0;
            for (uint32_t t = 0; t < N; t++)
                if (mu_tilde.permutation[t] == col_idx) { row_idx = t; break; }
            if (is_pivot_column[col_idx] == 1)
                pi_tilde[i].permutation[piv_idx++] = row_idx;
        }
        blind(&A_i, &cf_shake_state);
        const int cf_ok = CF(&A_i);
        if (cf_ok == 0) {
            *(linearized_rounds_seeds + i * SEED_LENGTH_BYTES) += 1;
            i -= 1;
        } else {
#if defined(USE_AVX2) || defined(USE_NEON)
            for (uint32_t sl = 0; sl < K; sl++)
                LESS_SHA3_INC_ABSORB(&state, A_i.values[sl], K);
#else
            LESS_SHA3_INC_ABSORB(&state, (uint8_t *)&A_i, sizeof(normalized_IS_t));
#endif
        }
    }

    /* ── Step 3: Compute the digest (challenge is now FIXED) ── */
    LESS_SHA3_INC_ABSORB(&state, (const uint8_t *)m, mlen);
    LESS_SHA3_INC_ABSORB(&state, sig->salt, HASH_DIGEST_LENGTH);
    LESS_SHA3_INC_FINALIZE(sig->digest, &state);

    uint8_t fixed_weight_string[T] = {0};
    SampleChallenge(fixed_weight_string, sig->digest);
    memcpy(out_challenge, fixed_weight_string, T);

    uint8_t indices_to_publish[T];
    for (uint32_t i = 0; i < T; i++)
        indices_to_publish[i] = !!(fixed_weight_string[i]);

    /* ╔══════════════════════════════════════════════════════════╗
     * ║  FAULT INJECTION POINT: corrupt seed_tree AFTER digest  ║
     * ║  but BEFORE GGMPath extracts the published nodes.       ║
     * ╚══════════════════════════════════════════════════════════╝ */
    if (fault_node >= 0 && fault_node < NUM_NODES_SEED_TREE) {
        seed_tree[fault_node * SEED_LENGTH_BYTES] ^= 0xFF;
    }

    /* ── Step 4: Extract GGM path (with potentially corrupted tree) ── */
    int emitted_monoms = 0;
    memset(&sig->seed_storage, 0, SEED_TREE_MAX_PUBLISHED_BYTES);

    const uint32_t num_seeds_published =
        GGMPath(seed_tree, indices_to_publish,
                (unsigned char *)&sig->seed_storage);

    monomial_action_IS_t mono_action;
    for (uint32_t i = 0; i < T; i++) {
        monomial_t Q_to_multiply;
        if (fixed_weight_string[i] != 0) {
            const int idx = fixed_weight_string[i];
            monomial_sample_prikey(&Q_to_multiply,
                                   private_monomial_seeds[idx - 1]);
            monomial_compose_action(&mono_action, &Q_to_multiply, &pi_tilde[i]);
            CosetRep(sig->cf_monom_actions[emitted_monoms], &mono_action);
            emitted_monoms++;
        }
    }
    return num_seeds_published;
}

/* ------------------------------------------------------------------ */
/*  Tree utility: find leaf nodes reachable from a given node         */
/* ------------------------------------------------------------------ */

#define LEFT_CHILD(i)  (2*(i)+1)

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

            int is_leaf = 0;
            int leaf_linear = -1;
            int running = 0;
            for (int s = 0; s < TREE_SUBROOTS; s++) {
                for (int j = 0; j < (int)cons_leaves[s]; j++) {
                    if ((int)(leaves_start_indices[s] + j) == nd) {
                        is_leaf = 1;
                        leaf_linear = running + j;
                    }
                }
                running += cons_leaves[s];
            }
            if (is_leaf) {
                leaves[(*count)++] = leaf_linear;
            } else if (level < LOG2(T)) {
                int lc = LEFT_CHILD(nd) - off[level];
                if (lc < NUM_NODES_SEED_TREE)     active[lc] = 1;
                if (lc + 1 < NUM_NODES_SEED_TREE) active[lc + 1] = 1;
            }
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

static int is_leaf_node(int node)
{
    const uint16_t cons_leaves[TREE_SUBROOTS]          = TREE_CONSECUTIVE_LEAVES;
    const uint16_t leaves_start_indices[TREE_SUBROOTS]  = TREE_LEAVES_START_INDICES;
    for (int s = 0; s < TREE_SUBROOTS; s++)
        for (int j = 0; j < (int)cons_leaves[s]; j++)
            if ((int)(leaves_start_indices[s] + j) == node) return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Attack mode 1: per-leaf safe-error scan                           */
/* ------------------------------------------------------------------ */

static void attack_per_leaf(const prikey_t *sk, const pubkey_t *pk,
                            const char *msg, uint64_t mlen)
{
    printf("node,level,is_leaf,verify_result,desc_leaves,"
           "ground_truth_published,ground_truth_withheld,"
           "oracle_says\n");

    /* We test all nodes (internal + leaf) */
    int tested = 0;
    for (int node = 0; node < NUM_NODES_SEED_TREE; node++) {
        sign_t sig;
        memset(&sig, 0, sizeof(sig));
        uint8_t challenge[T];

        size_t ns = LESS_sign_post_commit_fault(sk, msg, mlen, &sig,
                                                 node, challenge);
        (void)ns;

        int ok = LESS_verify(pk, msg, mlen, &sig);

        /* Ground truth from challenge */
        int desc[T], n_desc = 0;
        get_descendant_leaves(node, desc, &n_desc);
        int pub = 0, with = 0;
        for (int d = 0; d < n_desc; d++) {
            if (challenge[desc[d]] == 0) pub++;
            else with++;
        }

        const char *oracle;
        if (ok)
            oracle = "PASS:all_descendants_withheld";
        else
            oracle = "FAIL:has_published_descendant";

        printf("%d,%d,%d,%d,%d,%d,%d,%s\n",
               node, get_node_level(node), is_leaf_node(node),
               ok, n_desc, pub, with, oracle);

        tested++;
        if (tested % 20 == 0)
            fprintf(stderr, "  ... tested %d / %d nodes\n",
                    tested, NUM_NODES_SEED_TREE);
    }
    fprintf(stderr, "Done. %d nodes tested.\n", tested);
}

/* ------------------------------------------------------------------ */
/*  Attack mode 2: binary search to find all withheld leaves          */
/* ------------------------------------------------------------------ */

static void attack_binary_search(const prikey_t *sk, const pubkey_t *pk,
                                 const char *msg, uint64_t mlen)
{
    fprintf(stderr, "Binary search attack on GGM tree\n");
    fprintf(stderr, "Goal: recover challenge positions using minimal queries\n\n");

    /*
     * Strategy:
     *   Start from root. Fault root → always FAIL (has both published
     *   and withheld descendants). Then try each child:
     *   - If fault PASSES → all leaves in that subtree are withheld
     *     → mark them all as challenge ≠ 0, no need to recurse
     *   - If fault FAILS → at least one published leaf → recurse deeper
     *
     *   Continue until all leaves are classified.
     */
    int recovered_challenge[T];
    memset(recovered_challenge, -1, sizeof(recovered_challenge)); /* -1 = unknown */

    int total_queries = 0;

    /* BFS-style: queue of nodes to test */
    int queue[NUM_NODES_SEED_TREE];
    int q_head = 0, q_tail = 0;

    /* Start with root's children (root fault always fails) */
    const uint16_t off[LOG2(T)+1] = TREE_OFFSETS;
    int lc_root = LEFT_CHILD(0) - off[0];
    queue[q_tail++] = lc_root;
    queue[q_tail++] = lc_root + 1;

    while (q_head < q_tail) {
        int node = queue[q_head++];

        /* Get descendant leaves */
        int desc[T], n_desc = 0;
        get_descendant_leaves(node, desc, &n_desc);

        if (n_desc == 0) continue;

        /* Check if all descendants are already known */
        int all_known = 1;
        for (int d = 0; d < n_desc; d++) {
            if (recovered_challenge[desc[d]] == -1) {
                all_known = 0;
                break;
            }
        }
        if (all_known) continue;

        /* Perform a fault query */
        sign_t sig;
        memset(&sig, 0, sizeof(sig));
        uint8_t challenge[T];
        size_t ns = LESS_sign_post_commit_fault(sk, msg, mlen, &sig,
                                                 node, challenge);
        (void)ns;
        int ok = LESS_verify(pk, msg, mlen, &sig);
        total_queries++;

        if (ok) {
            /* SAFE ERROR: all descendants are withheld → challenge ≠ 0 */
            for (int d = 0; d < n_desc; d++)
                recovered_challenge[desc[d]] = 1; /* withheld */

            fprintf(stderr, "  query %3d: node %3d (level %d, %d leaves) "
                    "→ PASS → all withheld\n",
                    total_queries, node, get_node_level(node), n_desc);
        } else {
            /* Has at least one published descendant */
            if (n_desc == 1) {
                /* Leaf node → this leaf is published */
                recovered_challenge[desc[0]] = 0; /* published */
                fprintf(stderr, "  query %3d: node %3d (level %d, 1 leaf) "
                        "→ FAIL → leaf %d is published\n",
                        total_queries, node, get_node_level(node), desc[0]);
            } else {
                /* Internal node → recurse into children */
                int level = get_node_level(node);
                if (level < LOG2(T)) {
                    int lc = LEFT_CHILD(node) - off[level];
                    if (lc < NUM_NODES_SEED_TREE) {
                        queue[q_tail++] = lc;
                        queue[q_tail++] = lc + 1;
                    }
                }
                fprintf(stderr, "  query %3d: node %3d (level %d, %d leaves) "
                        "→ FAIL → recurse\n",
                        total_queries, node, get_node_level(node), n_desc);
            }
        }
    }

    /* Fill remaining unknowns: if we haven't classified a leaf, it must be
     * published (otherwise its ancestor would have been caught as safe-error) */
    for (int i = 0; i < T; i++) {
        if (recovered_challenge[i] == -1)
            recovered_challenge[i] = 0;
    }

    /* Verify against ground truth from the last signing */
    /* (We need one more clean signing to get the actual challenge) */
    sign_t golden_sig;
    memset(&golden_sig, 0, sizeof(golden_sig));
    uint8_t golden_challenge[T];
    LESS_sign_post_commit_fault(sk, msg, mlen, &golden_sig, -1, golden_challenge);

    int correct = 0, wrong = 0;
    int recovered_withheld = 0, actual_withheld = 0;
    for (int i = 0; i < T; i++) {
        int actual = (golden_challenge[i] != 0) ? 1 : 0;
        if (recovered_challenge[i] == actual) correct++;
        else wrong++;
        if (recovered_challenge[i] == 1) recovered_withheld++;
        if (actual) actual_withheld++;
    }

    printf("\n");
    printf("============================================================\n");
    printf("  Binary Search Attack Results\n");
    printf("============================================================\n");
    printf("Total signing queries used : %d\n", total_queries);
    printf("Correct classifications    : %d / %d\n", correct, T);
    printf("Wrong classifications      : %d / %d\n", wrong, T);
    printf("Recovered withheld count   : %d (actual: %d)\n",
           recovered_withheld, actual_withheld);
    printf("Challenge recovery rate    : %.1f%%\n",
           100.0 * correct / T);
    printf("\nRecovered challenge: ");
    for (int i = 0; i < T; i++) printf("%d", recovered_challenge[i]);
    printf("\nActual challenge   : ");
    for (int i = 0; i < T; i++) printf("%d", golden_challenge[i] ? 1 : 0);
    printf("\nMatch              : ");
    for (int i = 0; i < T; i++) printf("%c", recovered_challenge[i] == (golden_challenge[i] ? 1 : 0) ? '.' : 'X');
    printf("\n\n");

    if (wrong == 0)
        printf("★ FULL CHALLENGE RECOVERY ACHIEVED in %d queries ★\n\n", total_queries);
}

/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    const char *mode = (argc >= 2) ? argv[1] : "binary_search";

    fprintf(stderr, "=== LESS-252-192 Post-Commitment Safe-Error Attack ===\n");
    fprintf(stderr, "Mode: %s\n", mode);
    fprintf(stderr, "n=%d k=%d q=%d t=%d w=%d s=%d\n\n", N, K, Q, T, W, NUM_KEYPAIRS);

    /* Deterministic platform RNG */
    unsigned char pseed[32];
    for (int i = 0; i < 32; i++) pseed[i] = (unsigned char)(0x42 + i);
    initialize_csprng(&platform_csprng_state, pseed, 32);

    prikey_t sk;
    pubkey_t pk;
    LESS_keygen(&sk, &pk);

    const char *msg = "LESS post-commit fault test";
    uint64_t mlen = strlen(msg);

    if (strcmp(mode, "leaf") == 0 || strcmp(mode, "node") == 0) {
        attack_per_leaf(&sk, &pk, msg, mlen);
    } else {
        attack_binary_search(&sk, &pk, msg, mlen);
    }

    return 0;
}
