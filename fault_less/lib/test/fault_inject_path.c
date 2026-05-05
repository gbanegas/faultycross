/*
 * Fault-injection harness for LESS GGMPath side-channel analysis 

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
    FAULT_FLAG_FLIP   = 1,  /* flip a publish flag                   */
    FAULT_SKIP_NODE   = 2,  /* skip a node                          */
    FAULT_WRONG_FLAG  = 3,  /* flag an inappropriate node           */
    FAULT_ROOT        = 4,  /* reveal the root seed                 */
    FAULT_LABEL_LEAVES= 5,  /* corrupt leaf labelling               */
    FAULT_MODEL_COUNT
} fault_model_t;

static const char *fault_model_names[] = {
    "none", "flag_flip", "skip_node", "wrong_flag", "root", "label_leaves"
};

/* Global fault configuration — set before calling GGMPath_faulted */
static int          g_fault_target_node  = -1;   /* linearized index */
static fault_model_t g_fault_model       = FAULT_NONE;

#define TO_PUBLISH 0
#define NOT_TO_PUBLISH 1
#define LEFT_CHILD(i) (2*(i)+1)
#define RIGHT_CHILD(i) (2*(i)+2)
#define PARENT(i) ( ((i)%2) ? (((i)-1)/2) : (((i)-2)/2) )
#define SIBLING(i) ( ((i)%2) ? (i)+1 : (i)-1 )


static
void label_leaves(unsigned char flag_tree[NUM_NODES_SEED_TREE],
                     const unsigned char indices_to_publish[T])
{
    const uint16_t cons_leaves[TREE_SUBROOTS] = TREE_CONSECUTIVE_LEAVES;
    const uint16_t leaves_start_indices[TREE_SUBROOTS] = TREE_LEAVES_START_INDICES;

    unsigned int cnt = 0;
    for (size_t i=0; i<TREE_SUBROOTS; i++) {
        for (size_t j=0; j<cons_leaves[i]; j++) {
            flag_tree[leaves_start_indices[i]+j] = indices_to_publish[cnt];
            cnt++;
        }
    }
}


static
void label_leaves_faulted(unsigned char flag_tree[NUM_NODES_SEED_TREE],
                     const unsigned char indices_to_publish[T])
{
    const uint16_t cons_leaves[TREE_SUBROOTS] = TREE_CONSECUTIVE_LEAVES;
    const uint16_t leaves_start_indices[TREE_SUBROOTS] = TREE_LEAVES_START_INDICES;

    unsigned int cnt = 0;
    for (size_t i = 0; i < TREE_SUBROOTS; i++) {
        for (size_t j = 0; j < cons_leaves[i]; j++) {
            unsigned int node = leaves_start_indices[i] + j;
            unsigned char value = indices_to_publish[cnt];
            if (g_fault_model == FAULT_LABEL_LEAVES &&
                g_fault_target_node == (int)node) {
                /* Corrupt the leaf label at the chosen leaf */
                value = (value == TO_PUBLISH) ? NOT_TO_PUBLISH : TO_PUBLISH;
            }
            flag_tree[node] = value;
            cnt++;
        }
    }
}


static void compute_seeds_to_publish_faulted(
    /* linearized binary tree of boolean nodes containing
     * flags for each node 1-filled nodes are to be released */
    unsigned char flags_tree_to_publish[NUM_NODES_SEED_TREE],
    /* Boolean Array indicating which of the T seeds must be
     * released convention as per the above defines */
    const unsigned char indices_to_publish[T]) {
    /* the indices to publish may be less than the full leaves, copy them
     * into the linearized tree leaves */
    if (g_fault_model == FAULT_LABEL_LEAVES) {
        label_leaves_faulted(flags_tree_to_publish, indices_to_publish);
    } else {
        label_leaves(flags_tree_to_publish, indices_to_publish);
    }

    const uint16_t off[LOG2(T)+1] = TREE_OFFSETS;
    const uint16_t npl[LOG2(T)+1] = TREE_NODES_PER_LEVEL;
    const uint16_t leaves_start_indices[TREE_SUBROOTS] = TREE_LEAVES_START_INDICES;

    /* compute the value for the internal nodes of the tree starting from
     * the leaves, right to left */
    unsigned int start_node = leaves_start_indices[0];
    for (int level=LOG2(T); level>0; level--) {
        for (int i=npl[level]-2; i>=0; i-=2) {
            uint16_t current_node = start_node + i;
            uint16_t parent_node = PARENT(current_node) + (off[level-1] >> 1);
            if ((flags_tree_to_publish[current_node] == TO_PUBLISH) &&
                (flags_tree_to_publish[SIBLING(current_node)] == TO_PUBLISH)){
                 flags_tree_to_publish[parent_node] = TO_PUBLISH;
            } else {
                 flags_tree_to_publish[parent_node] = NOT_TO_PUBLISH;
            }
        }
        start_node -= npl[level-1];
    }
}

/*****************************************************************************/

uint32_t GGMPath_faulted(const unsigned char seed_tree[NUM_NODES_SEED_TREE*SEED_LENGTH_BYTES],
                 // INPUT: binary array storing in each cell a binary value (i.e., 0 or 1),
                 //        which in turn denotes if the seed of the node with the same index
                 //        must be released (i.e., cell == 0) or not (i.e., cell == 1).
                 //        Indeed, the seed will be stored in the sequence computed as a result into the out[...] array.
                 const unsigned char indices_to_publish[T], // INPUT: binary array denoting which node has to be released (cell == 0) or not
                 unsigned char *seed_storage)             // OUTPUT: sequence of seeds to be released
{
    /* complete linearized binary tree containing boolean values determining
     * if a node is to be released or not according to convention above.
     * */
    unsigned char flags_tree_to_publish[NUM_NODES_SEED_TREE] = {NOT_TO_PUBLISH};
    compute_seeds_to_publish_faulted(flags_tree_to_publish, indices_to_publish);

    /* ---- FAULT INJECTION ---- */
    if (g_fault_model != FAULT_NONE && g_fault_target_node >= 0 && g_fault_target_node < NUM_NODES_SEED_TREE) {
        switch (g_fault_model) {
        case FAULT_FLAG_FLIP:
            /* Flip the chosen publish flag */
            flags_tree_to_publish[g_fault_target_node] =
                (flags_tree_to_publish[g_fault_target_node] == TO_PUBLISH)
                    ? NOT_TO_PUBLISH
                    : TO_PUBLISH;
            break;
        case FAULT_SKIP_NODE:
            /* Skip publishing this node */
            flags_tree_to_publish[g_fault_target_node] = NOT_TO_PUBLISH;
            break;
        case FAULT_WRONG_FLAG:
            /* Flag an inappropriate node to publish */
            flags_tree_to_publish[g_fault_target_node] = TO_PUBLISH;
            break;
        case FAULT_ROOT:
            /* Reveal the root seed */
            flags_tree_to_publish[0] = TO_PUBLISH;  /* Root is node 0 */
            break;
        default:
            break;
        }
    }

    const uint16_t off[LOG2(T)+1] = TREE_OFFSETS;
    const uint16_t npl[LOG2(T)+1] = TREE_NODES_PER_LEVEL;

    /* no sense in trying to publish the root node, start examining from level 1 */
    int start_node = 1;
    int num_seeds_published = 0;

    for (int level = 1; level <= LOG2(T); level++){
        for (int node_in_level = 0; node_in_level < npl[level]; node_in_level++ ) {
            uint16_t current_node = start_node + node_in_level;
            uint16_t father_node = PARENT(current_node) + (off[level-1] >> 1);

            /* if seed is to be published and its ancestor/parent node is not,
             * add it to the seed storage */
            if ( (flags_tree_to_publish[current_node] == TO_PUBLISH) &&
                 (flags_tree_to_publish[father_node] == NOT_TO_PUBLISH) ) {
                memcpy(seed_storage + num_seeds_published*SEED_LENGTH_BYTES,
                        seed_tree + current_node*SEED_LENGTH_BYTES,
                        SEED_LENGTH_BYTES);
                num_seeds_published++;
            }
        }
        start_node += npl[level];
    }
   return num_seeds_published;
}

/* ------------------------------------------------------------------ */
/*  Modified LESS_sign that uses GGMPath_faulted                     */
/*  (Exact copy of LESS_sign from LESS.c, but calling                 */
/*   GGMPath_faulted instead of GGMPath)                            */
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

    /* Build the tree normally */
    BuildGGM(seed_tree, ephem_monomials_seed, sig->salt);

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
        GGMPath_faulted(seed_tree, indices_to_publish, (unsigned char *)&sig->seed_storage);

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
/*  Check if the root seed is revealed in the signature              */
/* ------------------------------------------------------------------ */

static int is_root_revealed(const sign_t *sig,
                            const unsigned char *expected_root_seed,
                            size_t num_seeds_published)
{
    /* Check if the root seed is in the published seeds */
    for (size_t i = 0; i < num_seeds_published; i++) {
        if (memcmp(sig->seed_storage + i * SEED_LENGTH_BYTES,
                   expected_root_seed, SEED_LENGTH_BYTES) == 0) {
            return 1;
        }
    }
    return 0;
}

static int is_internal_node(int node)
{
    const uint16_t npl[LOG2(T)+1] = TREE_NODES_PER_LEVEL;
    const uint16_t lpl[LOG2(T)+1] = TREE_LEAVES_PER_LEVEL;
    int start = 0;

    for (int level = 0; level <= LOG2(T); level++) {
        if (node >= start && node < start + npl[level]) {
            int node_in_level = node - start;
            return node_in_level < (int)(npl[level] - lpl[level]);
        }
        start += npl[level];
    }
    return 0;
}

static int leaf_index_to_node(int leaf_index)
{
    const uint16_t cons_leaves[TREE_SUBROOTS] = TREE_CONSECUTIVE_LEAVES;
    const uint16_t leaves_start_indices[TREE_SUBROOTS] = TREE_LEAVES_START_INDICES;
    int linear = 0;

    for (size_t i = 0; i < TREE_SUBROOTS; i++) {
        for (size_t j = 0; j < cons_leaves[i]; j++) {
            if (linear == leaf_index)
                return leaves_start_indices[i] + (int)j;
            linear++;
        }
    }
    return -1;
}
static void get_published_nodes(const unsigned char indices_to_publish[T],
                                int *published_nodes,
                                int *count)
{
    unsigned char flags_tree_to_publish[NUM_NODES_SEED_TREE] = {NOT_TO_PUBLISH};
    compute_seeds_to_publish_faulted(flags_tree_to_publish, indices_to_publish);

    const uint16_t off[LOG2(T)+1] = TREE_OFFSETS;
    const uint16_t npl[LOG2(T)+1] = TREE_NODES_PER_LEVEL;

    int start_node = 1;
    *count = 0;

    for (int level = 1; level <= LOG2(T); level++) {
        for (int node_in_level = 0; node_in_level < npl[level]; node_in_level++) {
            uint16_t current_node = start_node + node_in_level;
            uint16_t father_node = PARENT(current_node) + (off[level-1] >> 1);
            if (flags_tree_to_publish[current_node] == TO_PUBLISH &&
                flags_tree_to_publish[father_node] == NOT_TO_PUBLISH) {
                published_nodes[(*count)++] = current_node;
            }
        }
        start_node += npl[level];
    }
}

static void print_published_nodes(const unsigned char indices_to_publish[T])
{
    int published_nodes[T];
    int count = 0;
    get_published_nodes(indices_to_publish, published_nodes, &count);

    fprintf(stderr, "Published nodes in golden signature (%d):", count);
    for (int i = 0; i < count; i++) {
        fprintf(stderr, " %d", published_nodes[i]);
    }
    fprintf(stderr, "\n");
}
/* ------------------------------------------------------------------ */
/*  Main: run golden + faulted experiments                            */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    int specified_model = -1;
    int specified_target = -1;

    if (argc >= 2) {
        specified_model = atoi(argv[1]);
        if (specified_model < 0 || specified_model >= FAULT_MODEL_COUNT) {
            fprintf(stderr, "Usage: %s [fault_model_index] [target_index]\n", argv[0]);
            fprintf(stderr, "  fault_model_index: 0..%d (%s)\n",
                    FAULT_MODEL_COUNT - 1, fault_model_names[FAULT_MODEL_COUNT - 1]);
            fprintf(stderr, "  target_index: node index for skip_node/wrong_flag/root, leaf index for label_leaves\n");
            return 1;
        }
    }
    if (argc >= 3) {
        specified_target = atoi(argv[2]);
    }

    fprintf(stderr, "=== LESS GGMPath Fault Injection Test ===\n");

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

    /* Generate a fixed salt */
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

    uint8_t golden_challenge[T];
    unsigned char golden_indices_to_publish[T];
    SampleChallenge(golden_challenge, golden_sig.digest);
    for (uint32_t i = 0; i < T; i++)
        golden_indices_to_publish[i] = !!(golden_challenge[i]);
    print_published_nodes(golden_indices_to_publish);

    /* Extract the root seed from the golden signature context */
    /* In LESS_sign, the root seed is ephem_monomials_seed */
    /* We need to regenerate it to know what it is */
    SHAKE_STATE_STRUCT sk_shake_state;
    initialize_csprng(&sk_shake_state, sk.compressed_sk, PRIVATE_KEY_SEED_LENGTH_BYTES);
    unsigned char G_0_seed[SEED_LENGTH_BYTES];
    csprng_randombytes(G_0_seed, SEED_LENGTH_BYTES, &sk_shake_state);
    unsigned char private_monomial_seeds_dummy[NUM_KEYPAIRS - 1][PRIVATE_KEY_SEED_LENGTH_BYTES];
    for (uint32_t i = 0; i < NUM_KEYPAIRS - 1; i++) {
        csprng_randombytes(private_monomial_seeds_dummy[i], PRIVATE_KEY_SEED_LENGTH_BYTES, &sk_shake_state);
    }
    unsigned char root_seed[SEED_LENGTH_BYTES];
    csprng_randombytes(root_seed, SEED_LENGTH_BYTES, &sk_shake_state);

    int golden_root_revealed = is_root_revealed(&golden_sig, root_seed, golden_seeds);
    fprintf(stderr, "Golden root revealed: %s\n", golden_root_revealed ? "YES" : "NO");

    printf("model,target_type,target_index,target_node,verify,seeds_published,root_revealed\n");

    for (int model = FAULT_FLAG_FLIP; model < FAULT_MODEL_COUNT; model++) {
        if (specified_model >= 0 && model != specified_model) {
            continue;
        }

        fprintf(stderr, "\nTesting fault model: %s\n", fault_model_names[model]);
        g_fault_model = (fault_model_t)model;

        if (specified_target >= 0) {
            int target_node = -1;
            int target_index = specified_target;
            const char *target_type = "node";

            if (model == FAULT_LABEL_LEAVES) {
                target_node = leaf_index_to_node(specified_target);
                if (target_node < 0) {
                    fprintf(stderr, "Invalid leaf index %d\n", specified_target);
                    return 1;
                }
                target_type = "leaf";
            } else if (model == FAULT_ROOT) {
                target_node = 0;
            } else {
                if (specified_target < 0 || specified_target >= NUM_NODES_SEED_TREE) {
                    fprintf(stderr, "Invalid node index %d\n", specified_target);
                    return 1;
                }
                target_node = specified_target;
            }

            g_fault_target_node = target_node;
            sign_t faulted_sig;
            memset(&faulted_sig, 0, sizeof(faulted_sig));
            size_t faulted_seeds = LESS_sign_faulted(&sk, msg, mlen, &faulted_sig, fixed_salt);
            int faulted_ok = LESS_verify(&pk, msg, mlen, &faulted_sig);
            int root_revealed = is_root_revealed(&faulted_sig, root_seed, faulted_seeds);

            printf("%s,%s,%d,%d,%s,%zu,%s\n",
                   fault_model_names[model], target_type, target_index,
                   target_node, faulted_ok ? "ACCEPT" : "REJECT",
                   faulted_seeds, root_revealed ? "YES" : "NO");
            continue;
        }

        if (model == FAULT_ROOT) {
            g_fault_target_node = 0;
            sign_t faulted_sig;
            memset(&faulted_sig, 0, sizeof(faulted_sig));
            size_t faulted_seeds = LESS_sign_faulted(&sk, msg, mlen, &faulted_sig, fixed_salt);
            int faulted_ok = LESS_verify(&pk, msg, mlen, &faulted_sig);
            int root_revealed = is_root_revealed(&faulted_sig, root_seed, faulted_seeds);
            printf("%s,node,0,0,%s,%zu,%s\n",
                   fault_model_names[model], faulted_ok ? "ACCEPT" : "REJECT",
                   faulted_seeds, root_revealed ? "YES" : "NO");
            continue;
        }

        if (model == FAULT_LABEL_LEAVES) {
            for (int leaf_idx = 0; leaf_idx < T; leaf_idx++) {
                int target_node = leaf_index_to_node(leaf_idx);
                g_fault_target_node = target_node;
                sign_t faulted_sig;
                memset(&faulted_sig, 0, sizeof(faulted_sig));
                size_t faulted_seeds = LESS_sign_faulted(&sk, msg, mlen, &faulted_sig, fixed_salt);
                int faulted_ok = LESS_verify(&pk, msg, mlen, &faulted_sig);
                int root_revealed = is_root_revealed(&faulted_sig, root_seed, faulted_seeds);
                printf("%s,leaf,%d,%d,%s,%zu,%s\n",
                       fault_model_names[model], leaf_idx, target_node,
                       faulted_ok ? "ACCEPT" : "REJECT",
                       faulted_seeds, root_revealed ? "YES" : "NO");
            }
            continue;
        }

        for (int node = 0; node < NUM_NODES_SEED_TREE; node++) {
            if (!is_internal_node(node)) {
                continue;
            }
            g_fault_target_node = node;
            sign_t faulted_sig;
            memset(&faulted_sig, 0, sizeof(faulted_sig));
            size_t faulted_seeds = LESS_sign_faulted(&sk, msg, mlen, &faulted_sig, fixed_salt);
            int faulted_ok = LESS_verify(&pk, msg, mlen, &faulted_sig);
            int root_revealed = is_root_revealed(&faulted_sig, root_seed, faulted_seeds);
            printf("%s,node,%d,%d,%s,%zu,%s\n",
                   fault_model_names[model], node, node,
                   faulted_ok ? "ACCEPT" : "REJECT",
                   faulted_seeds, root_revealed ? "YES" : "NO");
        }
    }

    return 0;
}

/*****************************************************************************/
