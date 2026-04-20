/**
 * Post-Commitment Safe-Error Attack on LESS BuildGGM — FIXED oracle
 * =================================================================
 *
 * What changed vs post_commit_fault.c (original):
 * ------------------------------------------------
 * The original binary-search attack assumed:
 *   oracle(v) == PASS  ⇒  all descendant leaves of v are withheld
 *
 * That assumption is WRONG for window-B faults. The real oracle is:
 *   oracle(v) == FAIL  ⇔  v ∈ E
 * where E is the set of linearized node indices that GGMPath emits into
 * sig->seed_storage.
 *
 * Why: in window B the fault happens after BuildGGM. The tree children
 * are already derived and stored in seed_tree[]. GGMPath reads seed_tree[v]
 * ONLY when it is going to emit v. If v is not emitted, the fault at v
 * is a no-op — regardless of the challenge at v's descendants.
 *
 * Given the structure of compute_seeds_to_publish:
 *   flag[v] = TO_PUBLISH  ⇔  every leaf under v has ch == 0 (published)
 *   v ∈ E  ⇔  flag[v] == TO_PUBLISH  AND  flag[parent(v)] == NOT_TO_PUBLISH
 *
 * So E is exactly the set of MAXIMAL all-published subtrees. Recovering E
 * is equivalent to recovering the challenge:
 *   - leaf ℓ is published  ⇔  some ancestor of ℓ (possibly ℓ itself) is in E
 *   - leaf ℓ is withheld   ⇔  no ancestor of ℓ is in E
 *
 * Corrected BFS from the root:
 *   Invariant: every node we TEST is a "Case-C" node, meaning its
 *              flag is NOT_TO_PUBLISH and it has no emitted ancestor.
 *              (The root is trivially Case C whenever W > 0.)
 *   Step: for the current Case-C node v, test each child c:
 *         - FAIL → c is emitted, add to E, stop recursion on c's subtree
 *         - PASS → c must also be Case C (its parent is Case C, so any
 *                  ancestor of c either is c or is Case C — no ancestor
 *                  can be emitted, ruling out Case B). Recurse.
 *         - if c is a leaf and PASS: c is a withheld leaf.
 *
 * Expected query count for LESS-252-192 with |E| ≈ 65:
 *   roughly 2|E| + (tree depth contributions from the Case-C frontier),
 *   empirically ~130–220 queries. Information-theoretic lower bound is
 *   ⌈log₂ C(192, 36)⌉ ≈ 131 bits.
 *
 * Drop-in usage: compile alongside LESS (same link flags as the original
 * post_commit_fault) and run ./LESS_post_commit_fault_fixed.
 *
 * TODO (for the student):
 *   - Verify expected query count on 50 different signings (see LAB_NOTEBOOK B.1).
 *   - Instrument GGMPath to also dump E directly and cross-check the
 *     oracle's recovered_E against the ground truth (sanity guard).
 *   - Port the fix to post_commit_v2.c and attack_per_leaf in the
 *     original file — the per-leaf mode has the same bug but the
 *     symptom is different (it will report all leaves as published
 *     except the ones that happen to be emitted).
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

/* ----- tree-traversal primitives copied verbatim from the original ----- */

#define LEFT_CHILD(i)  (2*(i)+1)
#define RIGHT_CHILD(i) (2*(i)+2)
#define TO_PUBLISH     0
#define NOT_TO_PUBLISH 1

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

/* Return linearized leaf index for a given tree node, or -1 if not a leaf. */
static int leaf_linear_index(int node)
{
    const uint16_t cons_leaves[TREE_SUBROOTS]          = TREE_CONSECUTIVE_LEAVES;
    const uint16_t leaves_start_indices[TREE_SUBROOTS]  = TREE_LEAVES_START_INDICES;
    int running = 0;
    for (int s = 0; s < TREE_SUBROOTS; s++) {
        for (int j = 0; j < (int)cons_leaves[s]; j++) {
            if ((int)(leaves_start_indices[s] + j) == node) return running + j;
        }
        running += cons_leaves[s];
    }
    return -1;
}

/* Children of node v, respecting TREE_OFFSETS; writes -1 for missing children. */
static void children_of(int v, int *lc, int *rc)
{
    const uint16_t off[LOG2(T)+1] = TREE_OFFSETS;
    int level = get_node_level(v);
    if (level < 0 || level >= LOG2(T)) { *lc = *rc = -1; return; }
    int left = LEFT_CHILD(v) - off[level];
    if (left < 0 || left >= NUM_NODES_SEED_TREE) { *lc = *rc = -1; return; }
    *lc = left;
    *rc = left + 1;
    if (*rc >= NUM_NODES_SEED_TREE) *rc = -1;
}

/* ----- ground-truth computation of E (local reimplementation of -------- */
/* ----- compute_seeds_to_publish + GGMPath emission logic) -------------- */

/* Given challenge, fill `flags[0..NUM_NODES_SEED_TREE-1]` with TO_PUBLISH /
 * NOT_TO_PUBLISH exactly as compute_seeds_to_publish does, and mark
 * `emitted[v] = 1` iff GGMPath would emit v.
 *
 * Used ONLY for sanity checking in this file — the attacker cannot call
 * this because it requires the challenge, which is what we're recovering. */
static void compute_ground_truth_E(
    const uint8_t challenge[T],
    uint8_t flags[NUM_NODES_SEED_TREE],
    uint8_t emitted[NUM_NODES_SEED_TREE])
{
    /* Replicate label_leaves */
    const uint16_t cons_leaves[TREE_SUBROOTS]          = TREE_CONSECUTIVE_LEAVES;
    const uint16_t leaves_start_indices[TREE_SUBROOTS]  = TREE_LEAVES_START_INDICES;
    uint8_t indices_to_publish[T];
    for (uint32_t i = 0; i < T; i++) indices_to_publish[i] = !!(challenge[i]);

    memset(flags, NOT_TO_PUBLISH, NUM_NODES_SEED_TREE);

    /* Label leaves */
    unsigned int cnt = 0;
    for (size_t i = 0; i < TREE_SUBROOTS; i++) {
        for (size_t j = 0; j < cons_leaves[i]; j++) {
            flags[leaves_start_indices[i] + j] = indices_to_publish[cnt++];
        }
    }

    /* Propagate upward: flag[v] = TO_PUBLISH iff both children TO_PUBLISH */
    const uint16_t off[LOG2(T)+1] = TREE_OFFSETS;
    const uint16_t npl[LOG2(T)+1] = TREE_NODES_PER_LEVEL;
    unsigned int start_node = leaves_start_indices[0];
    for (int level = LOG2(T); level > 0; level--) {
        for (int i = npl[level] - 2; i >= 0; i -= 2) {
            uint16_t current = start_node + i;
            uint16_t parent  = ((current - 1) / 2) + (off[level-1] >> 1);
            uint16_t sibling = (current % 2) ? current + 1 : current - 1;
            if (flags[current] == TO_PUBLISH && flags[sibling] == TO_PUBLISH)
                flags[parent] = TO_PUBLISH;
            else
                flags[parent] = NOT_TO_PUBLISH;
        }
        start_node -= npl[level-1];
    }

    /* emitted[v] = (flag[v]==TO_PUBLISH AND flag[parent(v)]==NOT_TO_PUBLISH) */
    memset(emitted, 0, NUM_NODES_SEED_TREE);
    /* level 0 root is never emitted */
    start_node = 1;
    for (int level = 1; level <= LOG2(T); level++) {
        for (int i = 0; i < npl[level]; i++) {
            uint16_t current = start_node + i;
            uint16_t parent  = ((current - 1) / 2) + (off[level-1] >> 1);
            if (flags[current] == TO_PUBLISH && flags[parent] == NOT_TO_PUBLISH)
                emitted[current] = 1;
        }
        start_node += npl[level];
    }
}

/* ----- sign-with-fault: same as the original LESS_sign_post_commit_fault
 *       BUT accepts a forced salt. Every oracle query within ONE
 *       binary-search run must target the same underlying tree, and the
 *       salt is the only per-signature randomness that LESS_sign pulls
 *       from the platform CSPRNG (the ephemeral tree seed and cf_seed
 *       come from the SK-CSPRNG, which is reset from SK->compressed_sk
 *       at the top of every call — hence they are automatically constant
 *       across calls with the same SK).
 *
 *       Without pinning the salt, each call picks a fresh salt via
 *       randombytes() → fresh challenge → fresh E, and the accumulated
 *       oracle answers are mutually inconsistent. The original
 *       post_commit_fault.c had the same latent bug; the binary_search
 *       result there was coincidentally close to zero only because the
 *       oracle always returned PASS at level-1 subroots, stopping the
 *       BFS after 2 queries before the salt drift mattered. */

static size_t LESS_sign_post_commit_fault(
    const prikey_t *SK, const char *m, uint64_t mlen,
    sign_t *sig, int fault_node, uint8_t out_challenge[T],
    const unsigned char *forced_salt)           /* HASH_DIGEST_LENGTH bytes, or NULL for fresh */
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

    if (forced_salt != NULL)
        memcpy(sig->salt, forced_salt, HASH_DIGEST_LENGTH);
    else
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
    uint32_t nsp = GGMPath(seed_tree, itp, (unsigned char *)&sig->seed_storage);

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

/* ---------------------------------------------------------------------- */
/*  FIXED binary-search oracle                                            */
/*  Oracle contract:                                                       */
/*     fault(v) → verify == REJECT   ⇔   v ∈ E                            */
/*  The attack learns E top-down from the root.                            */
/* ---------------------------------------------------------------------- */

static void attack_binary_search_fixed(const prikey_t *sk, const pubkey_t *pk,
                                        const char *msg, uint64_t mlen)
{
    fprintf(stderr, "Binary search attack on GGM tree (FIXED oracle)\n");
    fprintf(stderr, "Goal: recover emitted-node set E, then reconstruct challenge\n\n");

    /* Step 0: do ONE clean signing to establish the target. Capture its
     * salt so every subsequent oracle query replays against the same tree
     * and the same challenge. */
    unsigned char target_salt[HASH_DIGEST_LENGTH];
    uint8_t target_challenge[T];
    {
        sign_t target_sig;
        memset(&target_sig, 0, sizeof(target_sig));
        LESS_sign_post_commit_fault(sk, msg, mlen, &target_sig, -1,
                                     target_challenge, NULL);
        memcpy(target_salt, target_sig.salt, HASH_DIGEST_LENGTH);

        int w_count = 0;
        for (int i = 0; i < T; i++) if (target_challenge[i]) w_count++;
        fprintf(stderr, "Target signing salt pinned. Challenge weight = %d / %d\n",
                w_count, T);
    }

    uint8_t recovered_emitted[NUM_NODES_SEED_TREE];
    memset(recovered_emitted, 0, sizeof(recovered_emitted));

    int queue[NUM_NODES_SEED_TREE];
    int q_head = 0, q_tail = 0;

    /* Start from children of the root (root itself is never emitted). */
    int lc, rc;
    children_of(0, &lc, &rc);
    if (lc >= 0) queue[q_tail++] = lc;
    if (rc >= 0) queue[q_tail++] = rc;

    int total_queries = 0;

    while (q_head < q_tail) {
        int node = queue[q_head++];

        /* Perform a fault query on this node — REPLAYED against target salt. */
        sign_t sig;
        memset(&sig, 0, sizeof(sig));
        uint8_t _ch[T];
        LESS_sign_post_commit_fault(sk, msg, mlen, &sig, node, _ch, target_salt);
        int ok = LESS_verify(pk, msg, mlen, &sig);
        total_queries++;

        /* Sanity: the replayed signing must produce the same challenge as
         * the target. If not, something's wrong with salt pinning. */
        if (memcmp(_ch, target_challenge, T) != 0) {
            fprintf(stderr, "  !! challenge drift at q%d node %d — salt pinning broken\n",
                    total_queries, node);
        }

        if (!ok) {
            /* FAIL → node is emitted. Stop, do not recurse into its subtree. */
            recovered_emitted[node] = 1;
            fprintf(stderr, "  q%3d: node %3d (lvl %d) → FAIL → E += {%d}\n",
                    total_queries, node, get_node_level(node), node);
        } else {
            /* PASS → node is Case C (since its parent was Case C by BFS
             * invariant). Recurse into children unless we're at a leaf. */
            if (is_leaf_node(node)) {
                int ll = leaf_linear_index(node);
                fprintf(stderr, "  q%3d: node %3d (lvl %d) = leaf %d → PASS → withheld\n",
                        total_queries, node, get_node_level(node), ll);
            } else {
                int cl, cr;
                children_of(node, &cl, &cr);
                if (cl >= 0) queue[q_tail++] = cl;
                if (cr >= 0) queue[q_tail++] = cr;
                fprintf(stderr, "  q%3d: node %3d (lvl %d) → PASS → recurse\n",
                        total_queries, node, get_node_level(node));
            }
        }
    }

    /* Reconstruct per-leaf challenge from recovered E.
     * Leaf ℓ is published iff some ancestor of ℓ is in E. */
    int recovered_challenge[T];
    for (int i = 0; i < T; i++) recovered_challenge[i] = 1; /* default: withheld */

    const uint16_t cons_leaves[TREE_SUBROOTS]          = TREE_CONSECUTIVE_LEAVES;
    const uint16_t leaves_start_indices[TREE_SUBROOTS]  = TREE_LEAVES_START_INDICES;
    int lin = 0;
    for (int s = 0; s < TREE_SUBROOTS; s++) {
        for (int j = 0; j < (int)cons_leaves[s]; j++) {
            int leaf_node = leaves_start_indices[s] + j;
            /* Walk up to the root, checking if any ancestor is in E. */
            int v = leaf_node;
            while (v > 0) {
                if (recovered_emitted[v]) {
                    recovered_challenge[lin] = 0; /* published */
                    break;
                }
                int level = get_node_level(v);
                if (level <= 0) break;
                const uint16_t off[LOG2(T)+1] = TREE_OFFSETS;
                v = ((v - 1) / 2) + (off[level-1] >> 1);
            }
            lin++;
        }
    }

    /* Compute ground-truth E from the target challenge (same signing). */
    uint8_t gt_flags[NUM_NODES_SEED_TREE];
    uint8_t gt_emitted[NUM_NODES_SEED_TREE];
    compute_ground_truth_E(target_challenge, gt_flags, gt_emitted);

    int E_correct = 0, E_wrong = 0, E_size_gt = 0, E_size_rec = 0;
    for (int v = 0; v < NUM_NODES_SEED_TREE; v++) {
        if (gt_emitted[v]) E_size_gt++;
        if (recovered_emitted[v]) E_size_rec++;
        if (recovered_emitted[v] == gt_emitted[v]) E_correct++;
        else E_wrong++;
    }

    int correct = 0, wrong = 0;
    int rec_withheld = 0, act_withheld = 0;
    for (int i = 0; i < T; i++) {
        int actual = (target_challenge[i] != 0) ? 1 : 0;
        if (recovered_challenge[i] == actual) correct++; else wrong++;
        if (recovered_challenge[i] == 1) rec_withheld++;
        if (actual) act_withheld++;
    }

    printf("\n============================================================\n");
    printf("  Binary Search Attack Results (FIXED, salt-pinned)\n");
    printf("============================================================\n");
    printf("Total signing queries used : %d\n", total_queries);
    printf("|E| ground truth           : %d\n", E_size_gt);
    printf("|E| recovered              : %d\n", E_size_rec);
    printf("E node agreement           : %d / %d\n", E_correct, NUM_NODES_SEED_TREE);
    printf("E node disagreement        : %d\n", E_wrong);
    printf("\n");
    printf("Challenge recovery         : %d / %d correct (%.1f%%)\n",
           correct, T, 100.0 * correct / T);
    printf("Withheld count rec/actual  : %d / %d\n", rec_withheld, act_withheld);
    printf("\nRecovered challenge: ");
    for (int i = 0; i < T; i++) printf("%d", recovered_challenge[i]);
    printf("\nActual challenge   : ");
    for (int i = 0; i < T; i++) printf("%d", target_challenge[i] ? 1 : 0);
    printf("\nMatch              : ");
    for (int i = 0; i < T; i++)
        printf("%c", recovered_challenge[i] == (target_challenge[i] ? 1 : 0) ? '.' : 'X');
    printf("\n\n");

    if (wrong == 0)
        printf("★ FULL CHALLENGE RECOVERY in %d queries ★\n\n", total_queries);
    else
        printf("Recovery incomplete. See E node disagreement above.\n\n");
}

/* ---------------------------------------------------------------------- */
int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    fprintf(stderr, "=== LESS-252-192 Post-Commitment Safe-Error (FIXED) ===\n");
    fprintf(stderr, "n=%d k=%d q=%d t=%d w=%d s=%d\n\n",
            N, K, Q, T, W, NUM_KEYPAIRS);

    unsigned char pseed[32];
    for (int i = 0; i < 32; i++) pseed[i] = (unsigned char)(0x42 + i);
    initialize_csprng(&platform_csprng_state, pseed, 32);

    prikey_t sk;
    pubkey_t pk;
    LESS_keygen(&sk, &pk);

    const char *msg = "LESS post-commit fault test";
    uint64_t mlen = strlen(msg);

    attack_binary_search_fixed(&sk, &pk, msg, mlen);
    return 0;
}
