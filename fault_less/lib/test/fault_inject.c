/**
 * Fault-injection harness for LESS BuildGGM side-channel analysis.
 *
 * This program:
 *  1. Generates a golden (fault-free) reference signature.
 *  2. For each internal node in the GGM tree, injects a fault and
 *     re-signs with the SAME keys/message/salt.
 *  3. Records whether the faulted signature still verifies.
 *  4. Outputs a CSV with per-node results for offline analysis.
 *
 * The CSV reveals the challenge string (which rounds use the secret
 * key) through a Safe-Error oracle: if faulting node X doesn't break
 * verification, then no published leaf descends from X.
 *
 * Build: cmake .. -DCMAKE_BUILD_TYPE=Debug && make LESS_fault_inject
 *   (with -DCATEGORY=252 -DTARGET=192)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "LESS.h"
#include "api.h"
#include "rng.h"
#include "seedtree.h"
#include "parameters.h"
#include "utils.h"

/* ------------------------------------------------------------------ */
/*  Fault models                                                      */
/* ------------------------------------------------------------------ */

typedef enum {
    FAULT_NONE        = 0,  /* golden reference                     */
    FAULT_SKIP_EXPAND = 1,  /* skip CSPRNG expansion (children = 0) */
    FAULT_BITFLIP     = 2,  /* flip bit 0 of the parent seed        */
    FAULT_ZERO_SEED   = 3,  /* set parent seed to all-zero          */
    FAULT_WRONG_DS    = 4,  /* corrupt domain-separation index      */
    FAULT_MODEL_COUNT
} fault_model_t;

static const char *fault_model_names[] = {
    "none", "skip_expand", "bitflip", "zero_seed", "wrong_domain_sep"
};

/* Global fault configuration — set before calling BuildGGM_faulted */
static int          g_fault_target_node  = -1;   /* linearized index */
static fault_model_t g_fault_model       = FAULT_NONE;

/* ------------------------------------------------------------------ */
/*  Modified BuildGGM with injectable faults                          */
/* ------------------------------------------------------------------ */

#define LEFT_CHILD(i)  (2*(i)+1)
#define RIGHT_CHILD(i) (2*(i)+2)

void BuildGGM_faulted(unsigned char seed_tree[NUM_NODES_SEED_TREE * SEED_LENGTH_BYTES],
                      const unsigned char root_seed[SEED_LENGTH_BYTES],
                      const unsigned char salt[HASH_DIGEST_LENGTH])
{
    const uint32_t csprng_input_len = SALT_LENGTH_BYTES + SEED_LENGTH_BYTES;
    unsigned char csprng_input[csprng_input_len];
    SHAKE_STATE_STRUCT tree_csprng_state;
    memcpy(csprng_input + SEED_LENGTH_BYTES, salt, SALT_LENGTH_BYTES);

    memcpy(seed_tree, root_seed, SEED_LENGTH_BYTES);

    const uint16_t off[LOG2(T)+1] = TREE_OFFSETS;
    const uint16_t npl[LOG2(T)+1] = TREE_NODES_PER_LEVEL;
    const uint16_t lpl[LOG2(T)+1] = TREE_LEAVES_PER_LEVEL;

    int start_node = 0;
    for (int level = 0; level < LOG2(T); level++) {
        for (int node_in_level = 0; node_in_level < npl[level] - lpl[level]; node_in_level++) {
            uint16_t father_node     = start_node + node_in_level;
            uint16_t left_child_node = LEFT_CHILD(father_node) - off[level];

            /* ---- FAULT INJECTION POINT ---- */
            if ((int)father_node == g_fault_target_node) {
                switch (g_fault_model) {
                case FAULT_SKIP_EXPAND:
                    /* Skip the expansion entirely; children stay zero */
                    continue;

                case FAULT_BITFLIP:
                    /* Flip bit 0 of the parent seed before expansion */
                    seed_tree[father_node * SEED_LENGTH_BYTES] ^= 0x01;
                    break;

                case FAULT_ZERO_SEED:
                    /* Zero the parent seed */
                    memset(seed_tree + father_node * SEED_LENGTH_BYTES,
                           0, SEED_LENGTH_BYTES);
                    break;

                case FAULT_WRONG_DS:
                    /* Will corrupt domain_sep below */
                    break;

                default:
                    break;
                }
            }

            /* Prepare CSPRNG input */
            memcpy(csprng_input,
                   seed_tree + father_node * SEED_LENGTH_BYTES,
                   SEED_LENGTH_BYTES);

            uint16_t domain_sep = father_node;

            /* Corrupt domain separation if this is the target */
            if ((int)father_node == g_fault_target_node &&
                g_fault_model == FAULT_WRONG_DS) {
                domain_sep ^= 0xFFFF;
            }

            initialize_csprng_ds(&tree_csprng_state, csprng_input,
                                 csprng_input_len, domain_sep);
            csprng_randombytes(seed_tree + left_child_node * SEED_LENGTH_BYTES,
                               2 * SEED_LENGTH_BYTES,
                               &tree_csprng_state);
        }
        start_node += npl[level];
    }
}

/* ------------------------------------------------------------------ */
/*  Modified LESS_sign that uses BuildGGM_faulted                     */
/*  (Exact copy of LESS_sign from LESS.c, but calling                 */
/*   BuildGGM_faulted instead of BuildGGM)                            */
/* ------------------------------------------------------------------ */

/* We need access to internal functions — include them here */
#include "canonical.h"
#include "fips202.h"
#include "sha3.h"
#include "monomial_mat.h"
#include "codes.h"

size_t LESS_sign_faulted(const prikey_t *SK,
                         const char *const m,
                         const uint64_t mlen,
                         sign_t *sig,
                         const unsigned char forced_salt[HASH_DIGEST_LENGTH])
{
    uint8_t g0_initial_pivot_flags[N_pad];
    uint8_t is_pivot_column[N_pad];

    SHAKE_STATE_STRUCT sk_shake_state;
    initialize_csprng(&sk_shake_state, SK->compressed_sk,
                      PRIVATE_KEY_SEED_LENGTH_BYTES);

    unsigned char G_0_seed[SEED_LENGTH_BYTES];
    csprng_randombytes(G_0_seed, SEED_LENGTH_BYTES, &sk_shake_state);

    unsigned char private_monomial_seeds[NUM_KEYPAIRS - 1][PRIVATE_KEY_SEED_LENGTH_BYTES];
    for (uint32_t i = 0; i < NUM_KEYPAIRS - 1; i++) {
        csprng_randombytes(private_monomial_seeds[i],
                           PRIVATE_KEY_SEED_LENGTH_BYTES,
                           &sk_shake_state);
    }

    /* Use the FORCED salt (same across golden & faulted runs) */
    memcpy(sig->salt, forced_salt, HASH_DIGEST_LENGTH);

    unsigned char ephem_monomials_seed[SEED_LENGTH_BYTES];
    csprng_randombytes(ephem_monomials_seed, SEED_LENGTH_BYTES, &sk_shake_state);

    uint8_t cf_seed[SEED_LENGTH_BYTES];
    csprng_randombytes(cf_seed, SEED_LENGTH_BYTES, &sk_shake_state);
    SHAKE_STATE_STRUCT cf_shake_state;
    initialize_csprng(&cf_shake_state, cf_seed, SEED_LENGTH_BYTES);

    unsigned char seed_tree[NUM_NODES_SEED_TREE * SEED_LENGTH_BYTES];
    memset(seed_tree, 0, sizeof(seed_tree));

    /* ---- THE KEY DIFFERENCE: faulted BuildGGM ---- */
    BuildGGM_faulted(seed_tree, ephem_monomials_seed, sig->salt);

    unsigned char linearized_rounds_seeds[T * SEED_LENGTH_BYTES];
    memset(linearized_rounds_seeds, 0, sizeof(linearized_rounds_seeds));
    seed_leaves(linearized_rounds_seeds, seed_tree);

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
        uint8_t permuted_pivot_flags[N_pad];
        for (uint32_t t = 0; t < N; t++)
            permuted_pivot_flags[mu_tilde.permutation[t]] = g0_initial_pivot_flags[t];
        if (generator_RREF_pivot_reuse(&G0, is_pivot_column,
                                        permuted_pivot_flags,
                                        SIGN_PIVOT_REUSE_LIMIT) == 0)
            return 0;
#else
        if (generator_RREF(&G0, is_pivot_column) == 0)
            return 0;
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
            for (uint32_t t = 0; t < N; t++) {
                if (mu_tilde.permutation[t] == col_idx) { row_idx = t; break; }
            }
            if (is_pivot_column[col_idx] == 1) {
                pi_tilde[i].permutation[piv_idx] = row_idx;
                piv_idx++;
            }
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

    LESS_SHA3_INC_ABSORB(&state, (const uint8_t *)m, mlen);
    LESS_SHA3_INC_ABSORB(&state, sig->salt, HASH_DIGEST_LENGTH);
    LESS_SHA3_INC_FINALIZE(sig->digest, &state);

    uint8_t fixed_weight_string[T] = {0};
    SampleChallenge(fixed_weight_string, sig->digest);

    uint8_t indices_to_publish[T];
    for (uint32_t i = 0; i < T; i++)
        indices_to_publish[i] = !!(fixed_weight_string[i]);

    int emitted_monoms = 0;
    memset(&sig->seed_storage, 0, SEED_TREE_MAX_PUBLISHED_BYTES);

    const uint32_t num_seeds_published =
        GGMPath(seed_tree, indices_to_publish, (unsigned char *)&sig->seed_storage);

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
/*  Utility: compute which leaf indices descend from a given node     */
/* ------------------------------------------------------------------ */

static void get_descendant_leaves(int node, int *leaf_indices, int *count)
{
    const uint16_t off[LOG2(T)+1]  = TREE_OFFSETS;
    const uint16_t npl[LOG2(T)+1]  = TREE_NODES_PER_LEVEL;
    const uint16_t cons_leaves[TREE_SUBROOTS]         = TREE_CONSECUTIVE_LEAVES;
    const uint16_t leaves_start_indices[TREE_SUBROOTS] = TREE_LEAVES_START_INDICES;

    /* Build a set of "active" nodes — start with just {node},
     * then expand children level by level */
    int active[NUM_NODES_SEED_TREE];
    memset(active, 0, sizeof(active));
    active[node] = 1;

    *count = 0;

    int start = 0;
    for (int level = 0; level <= LOG2(T); level++) {
        for (int i = 0; i < npl[level]; i++) {
            int nd = start + i;
            if (!active[nd]) continue;

            /* Check if this node is a leaf */
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
                leaf_indices[(*count)++] = leaf_linear;
            } else if (level < LOG2(T)) {
                /* Mark children active */
                int lc = LEFT_CHILD(nd) - off[level];
                int rc = lc + 1;
                if (lc < NUM_NODES_SEED_TREE) active[lc] = 1;
                if (rc < NUM_NODES_SEED_TREE) active[rc] = 1;
            }
        }
        start += npl[level];
    }
}

/* ------------------------------------------------------------------ */
/*  Determine the level of a node in the linearized tree              */
/* ------------------------------------------------------------------ */

static int get_node_level(int node)
{
    const uint16_t npl[LOG2(T)+1] = TREE_NODES_PER_LEVEL;
    int start = 0;
    for (int level = 0; level <= LOG2(T); level++) {
        if (node >= start && node < start + npl[level])
            return level;
        start += npl[level];
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Determine how many internal (non-leaf) nodes exist                */
/* ------------------------------------------------------------------ */

static int count_internal_nodes(void)
{
    const uint16_t npl[LOG2(T)+1] = TREE_NODES_PER_LEVEL;
    const uint16_t lpl[LOG2(T)+1] = TREE_LEAVES_PER_LEVEL;

    int total = 0;
    for (int level = 0; level <= LOG2(T); level++)
        total += npl[level] - lpl[level];
    return total;
}

/* ------------------------------------------------------------------ */
/*  Check if a node is an internal (expandable) node                  */
/* ------------------------------------------------------------------ */

static int is_internal_node(int node)
{
    const uint16_t npl[LOG2(T)+1] = TREE_NODES_PER_LEVEL;
    const uint16_t lpl[LOG2(T)+1] = TREE_LEAVES_PER_LEVEL;

    int start = 0;
    for (int level = 0; level <= LOG2(T); level++) {
        int node_in_level = node - start;
        if (node_in_level >= 0 && node_in_level < npl[level]) {
            return (node_in_level < npl[level] - lpl[level]) ? 1 : 0;
        }
        start += npl[level];
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Main: run golden + faulted experiments                            */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    /* Parse optional fault model argument */
    fault_model_t model = FAULT_ZERO_SEED;
    int max_faults = -1;  /* -1 = all internal nodes */

    if (argc >= 2) {
        int m = atoi(argv[1]);
        if (m >= 0 && m < FAULT_MODEL_COUNT) model = (fault_model_t)m;
    }
    if (argc >= 3) {
        max_faults = atoi(argv[2]);
    }

    fprintf(stderr, "=== LESS-252-192 Fault Injection Campaign ===\n");
    fprintf(stderr, "Fault model : %s (%d)\n", fault_model_names[model], model);
    fprintf(stderr, "Parameters  : n=%d k=%d q=%d t=%d w=%d s=%d\n",
            N, K, Q, T, W, NUM_KEYPAIRS);
    fprintf(stderr, "Tree nodes  : %d  (internal: %d)\n",
            NUM_NODES_SEED_TREE, count_internal_nodes());

    /* Initialize platform CSPRNG deterministically */
    unsigned char platform_seed[32];
    for (int i = 0; i < 32; i++) platform_seed[i] = (unsigned char)(0x42 + i);
    initialize_csprng(&platform_csprng_state, platform_seed, 32);

    /* Key generation */
    prikey_t sk;
    pubkey_t pk;
    LESS_keygen(&sk, &pk);

    const char *msg = "LESS fault analysis test message";
    uint64_t mlen = strlen(msg);

    /* Generate a fixed salt (so golden and faulted runs use the same one) */
    unsigned char fixed_salt[HASH_DIGEST_LENGTH];
    randombytes(fixed_salt, HASH_DIGEST_LENGTH);

    /* ---- Golden run ---- */
    fprintf(stderr, "Running golden (fault-free) signature...\n");
    g_fault_model       = FAULT_NONE;
    g_fault_target_node  = -1;

    sign_t golden_sig;
    memset(&golden_sig, 0, sizeof(golden_sig));
    size_t golden_seeds = LESS_sign_faulted(&sk, msg, mlen, &golden_sig, fixed_salt);

    int golden_ok = LESS_verify(&pk, msg, mlen, &golden_sig);
    fprintf(stderr, "Golden verify: %s  (seeds published: %zu)\n",
            golden_ok ? "ACCEPT" : "REJECT", golden_seeds);
    if (!golden_ok) {
        fprintf(stderr, "ERROR: golden signature failed verification!\n");
        return 1;
    }

    /* Extract the golden challenge string */
    uint8_t golden_challenge[T];
    SampleChallenge(golden_challenge, golden_sig.digest);

    /* ---- CSV header ---- */
    printf("node,level,fault_model,verify_result,sig_matches_golden,"
           "digest_matches,seeds_match,num_descendant_leaves,"
           "descendant_published,descendant_withheld,"
           "leaked_info\n");

    /* ---- Fault each internal node ---- */
    int faults_done = 0;
    g_fault_model = model;

    for (int node = 0; node < NUM_NODES_SEED_TREE; node++) {
        if (!is_internal_node(node)) continue;
        if (max_faults > 0 && faults_done >= max_faults) break;

        g_fault_target_node = node;

        sign_t faulted_sig;
        memset(&faulted_sig, 0, sizeof(faulted_sig));
        size_t faulted_seeds = LESS_sign_faulted(&sk, msg, mlen,
                                                  &faulted_sig, fixed_salt);
        (void)faulted_seeds;

        int faulted_ok = LESS_verify(&pk, msg, mlen, &faulted_sig);

        /* Compare signatures */
        int sig_matches  = (memcmp(&golden_sig, &faulted_sig, sizeof(sign_t)) == 0);
        int digest_match = (memcmp(golden_sig.digest, faulted_sig.digest,
                                   HASH_DIGEST_LENGTH) == 0);
        int seeds_match  = (memcmp(golden_sig.seed_storage, faulted_sig.seed_storage,
                                   SEED_TREE_MAX_PUBLISHED_BYTES) == 0);

        /* Compute descendant leaf info */
        int desc_leaves[T];
        int n_desc = 0;
        get_descendant_leaves(node, desc_leaves, &n_desc);

        int desc_published = 0, desc_withheld = 0;
        for (int d = 0; d < n_desc; d++) {
            if (golden_challenge[desc_leaves[d]] == 0)
                desc_published++;
            else
                desc_withheld++;
        }

        /* Determine what was leaked */
        const char *leaked;
        if (faulted_ok && !sig_matches) {
            /* Signature changed but still valid — different challenge path */
            leaked = "digest_changed_new_valid_sig";
        } else if (faulted_ok && sig_matches) {
            /* No effect — all descendants were withheld */
            leaked = "safe_error:all_descendants_withheld";
        } else if (!faulted_ok && desc_published > 0) {
            leaked = "verify_fail:has_published_descendants";
        } else if (!faulted_ok && desc_published == 0) {
            leaked = "verify_fail:unexpected";
        } else {
            leaked = "unknown";
        }

        int level = get_node_level(node);

        printf("%d,%d,%s,%d,%d,%d,%d,%d,%d,%d,%s\n",
               node, level, fault_model_names[model],
               faulted_ok, sig_matches, digest_match, seeds_match,
               n_desc, desc_published, desc_withheld,
               leaked);

        faults_done++;

        if (faults_done % 20 == 0)
            fprintf(stderr, "  ... faulted %d / %d internal nodes\n",
                    faults_done, count_internal_nodes());
    }

    fprintf(stderr, "Done. %d faults injected.\n", faults_done);
    return 0;
}
