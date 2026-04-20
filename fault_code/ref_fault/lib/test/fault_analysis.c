/**
 * Fault analysis harness for LESS BuildGGM.
 *
 * Performs keygen + sign + verify, then prints the full signature
 * broken down by fields (digest, salt, seed_storage, cf_monom_actions).
 *
 * Build with: -DCATEGORY=252 -DTARGET=192
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
/*  Pretty-print helpers                                              */
/* ------------------------------------------------------------------ */

static void print_hex(const char *label,
                      const unsigned char *data,
                      size_t len)
{
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 32 == 0)
            printf("\n");
    }
    if (len % 32 != 0)
        printf("\n");
    printf("\n");
}

/* ------------------------------------------------------------------ */
/*  Print every field of a sign_t structure                           */
/* ------------------------------------------------------------------ */

static void print_signature_fields(const sign_t *sig,
                                   uint32_t num_seeds_published)
{
    printf("============================================================\n");
    printf("  LESS-252-192 Signature Dump\n");
    printf("============================================================\n\n");

    /* 1. Digest (commitment hash) */
    print_hex("digest (cmt)", sig->digest, HASH_DIGEST_LENGTH);

    /* 2. Salt */
    print_hex("salt", sig->salt, HASH_DIGEST_LENGTH);

    /* 3. Seed storage (GGM path) */
    printf("num_seeds_published = %u\n", num_seeds_published);
    printf("SEED_LENGTH_BYTES   = %u\n", SEED_LENGTH_BYTES);
    uint32_t seed_storage_bytes = num_seeds_published * SEED_LENGTH_BYTES + 1;
    print_hex("seed_storage (GGM path)",
              sig->seed_storage,
              seed_storage_bytes);

    /* 4. Coset representative actions (W of them, each N8 bytes) */
    printf("W  = %u  (number of non-zero challenges)\n", W);
    printf("N8 = %u  (bytes per coset rep)\n", N8);
    for (uint32_t i = 0; i < W; i++) {
        char label[64];
        snprintf(label, sizeof(label), "cf_monom_actions[%u]", i);
        print_hex(label, sig->cf_monom_actions[i], N8);
    }

    /* 5. Overall sizes */
    uint32_t sig_wire_size = LESS_SIGNATURE_SIZE(num_seeds_published);
    printf("------------------------------------------------------------\n");
    printf("Worst-case sig struct size : %zu bytes\n", sizeof(sign_t));
    printf("Actual wire signature size : %u bytes\n", sig_wire_size);
    printf("  = digest(%u) + salt(%u) + seeds(%u) + coset_reps(%u) + 1\n",
           HASH_DIGEST_LENGTH,
           HASH_DIGEST_LENGTH,
           num_seeds_published * SEED_LENGTH_BYTES,
           W * N8);
    printf("============================================================\n\n");
}

/* ------------------------------------------------------------------ */
/*  Print the full GGM seed tree (all internal nodes + leaves)        */
/* ------------------------------------------------------------------ */

static void print_ggm_seed_tree(const unsigned char *seed_tree)
{
    printf("============================================================\n");
    printf("  Full GGM Seed Tree (%d nodes, %d bytes each)\n",
           NUM_NODES_SEED_TREE, SEED_LENGTH_BYTES);
    printf("============================================================\n\n");

    for (int i = 0; i < NUM_NODES_SEED_TREE; i++) {
        printf("node[%3d]: ", i);
        for (int j = 0; j < SEED_LENGTH_BYTES; j++) {
            printf("%02X", seed_tree[i * SEED_LENGTH_BYTES + j]);
        }
        printf("\n");
    }
    printf("\n");
}

/* ------------------------------------------------------------------ */
/*  Print the leaf seeds extracted from the tree                      */
/* ------------------------------------------------------------------ */

static void print_leaf_seeds(const unsigned char *seed_tree)
{
    unsigned char leaves[T * SEED_LENGTH_BYTES];
    /* Use a mutable copy since seed_leaves expects non-const */
    unsigned char tree_copy[NUM_NODES_SEED_TREE * SEED_LENGTH_BYTES];
    memcpy(tree_copy, seed_tree, sizeof(tree_copy));
    seed_leaves(leaves, tree_copy);

    printf("============================================================\n");
    printf("  Leaf Seeds (T=%d rounds)\n", T);
    printf("============================================================\n\n");
    for (int i = 0; i < T; i++) {
        printf("seed(%3d): ", i);
        for (int j = 0; j < SEED_LENGTH_BYTES; j++) {
            printf("%02X", leaves[i * SEED_LENGTH_BYTES + j]);
        }
        printf("\n");
    }
    printf("\n");
}

/* ------------------------------------------------------------------ */
/*  Standalone BuildGGM test: build tree, print it, print leaves      */
/* ------------------------------------------------------------------ */

static void test_build_ggm(void)
{
    printf("############################################################\n");
    printf("#  Standalone BuildGGM test                                 #\n");
    printf("############################################################\n\n");

    /* Use a fixed root seed for reproducibility */
    unsigned char root_seed[SEED_LENGTH_BYTES];
    unsigned char salt[HASH_DIGEST_LENGTH];

    /* Fill with deterministic pattern so the run is reproducible */
    for (int i = 0; i < SEED_LENGTH_BYTES; i++)
        root_seed[i] = (unsigned char)(0xAA ^ i);
    for (int i = 0; i < HASH_DIGEST_LENGTH; i++)
        salt[i] = (unsigned char)(0xBB ^ i);

    print_hex("root_seed", root_seed, SEED_LENGTH_BYTES);
    print_hex("salt",      salt,      HASH_DIGEST_LENGTH);

    unsigned char seed_tree[NUM_NODES_SEED_TREE * SEED_LENGTH_BYTES];
    memset(seed_tree, 0, sizeof(seed_tree));

    BuildGGM(seed_tree, root_seed, salt);

    print_ggm_seed_tree(seed_tree);
    print_leaf_seeds(seed_tree);
}

/* ------------------------------------------------------------------ */
/*  Full keygen → sign → verify flow with signature dump              */
/* ------------------------------------------------------------------ */

static void test_sign_verify(void)
{
    printf("############################################################\n");
    printf("#  Full Keygen + Sign + Verify                              #\n");
    printf("############################################################\n\n");

    /* Print parameter summary */
    printf("Parameters:\n");
    printf("  CATEGORY = 252  (NIST Cat 1)\n");
    printf("  TARGET   = 192\n");
    printf("  n = %d, k = %d, q = %d\n", N, K, Q);
    printf("  t = %d, w = %d, s = %d\n", T, W, NUM_KEYPAIRS);
    printf("  SEED_LENGTH_BYTES      = %d\n", SEED_LENGTH_BYTES);
    printf("  HASH_DIGEST_LENGTH     = %d\n", HASH_DIGEST_LENGTH);
    printf("  NUM_NODES_SEED_TREE    = %d\n", NUM_NODES_SEED_TREE);
    printf("  MAX_PUBLISHED_SEEDS    = %d\n", MAX_PUBLISHED_SEEDS);
    printf("  SEED_TREE_MAX_PUB_BYTES= %d\n", SEED_TREE_MAX_PUBLISHED_BYTES);
    printf("  sizeof(pubkey_t)       = %zu\n", sizeof(pubkey_t));
    printf("  sizeof(prikey_t)       = %zu\n", sizeof(prikey_t));
    printf("  sizeof(sign_t)         = %zu\n", sizeof(sign_t));
    printf("\n");

    /* Initialize platform CSPRNG deterministically for reproducibility */
    unsigned char platform_seed[32];
    for (int i = 0; i < 32; i++)
        platform_seed[i] = (unsigned char)(0x42 + i);
    initialize_csprng(&platform_csprng_state, platform_seed, 32);

    /* Key generation */
    prikey_t sk;
    pubkey_t pk;
    LESS_keygen(&sk, &pk);
    print_hex("secret key (compressed seed)", sk.compressed_sk,
              PRIVATE_KEY_SEED_LENGTH_BYTES);
    print_hex("public key seed (G_0_seed)", pk.G_0_seed, SEED_LENGTH_BYTES);

    /* Sign a short test message */
    const char *msg = "LESS fault analysis test message";
    uint64_t mlen = strlen(msg);
    printf("Message: \"%s\" (%llu bytes)\n\n", msg, (unsigned long long)mlen);

    sign_t sig;
    memset(&sig, 0, sizeof(sig));
    size_t num_seeds = LESS_sign(&sk, msg, mlen, &sig);

    printf("LESS_sign returned num_seeds_published = %zu\n\n", num_seeds);

    /* Print full signature */
    print_signature_fields(&sig, (uint32_t)num_seeds);

    /* Verify */
    int ok = LESS_verify(&pk, msg, mlen, &sig);
    printf("LESS_verify result: %s (%d)\n\n", ok ? "ACCEPT" : "REJECT", ok);

    /* --- Also dump the GGM tree produced during signing ---
     * Re-derive the tree exactly as LESS_sign does internally,
     * so the researcher can correlate tree nodes with the signature. */
    printf("############################################################\n");
    printf("#  Re-derived GGM tree (same seeds as used in signing)      #\n");
    printf("############################################################\n\n");

    /* Re-expand the private key to get the ephemeral seed */
    SHAKE_STATE_STRUCT sk_shake;
    initialize_csprng(&sk_shake, sk.compressed_sk, PRIVATE_KEY_SEED_LENGTH_BYTES);
    unsigned char G_0_seed[SEED_LENGTH_BYTES];
    csprng_randombytes(G_0_seed, SEED_LENGTH_BYTES, &sk_shake);
    /* skip private monomial seeds */
    unsigned char dummy[PRIVATE_KEY_SEED_LENGTH_BYTES];
    for (uint32_t i = 0; i < NUM_KEYPAIRS - 1; i++)
        csprng_randombytes(dummy, PRIVATE_KEY_SEED_LENGTH_BYTES, &sk_shake);
    /* the ephemeral seed tree seed */
    unsigned char ephem_seed[SEED_LENGTH_BYTES];
    csprng_randombytes(ephem_seed, SEED_LENGTH_BYTES, &sk_shake);

    print_hex("ephemeral tree root seed", ephem_seed, SEED_LENGTH_BYTES);
    print_hex("salt used", sig.salt, HASH_DIGEST_LENGTH);

    unsigned char re_tree[NUM_NODES_SEED_TREE * SEED_LENGTH_BYTES];
    memset(re_tree, 0, sizeof(re_tree));
    BuildGGM(re_tree, ephem_seed, sig.salt);

    print_ggm_seed_tree(re_tree);
    print_leaf_seeds(re_tree);

    /* Print the challenge string so the researcher knows which
     * leaves were withheld vs. published */
    uint8_t challenge[T];
    SampleChallenge(challenge, sig.digest);
    printf("Challenge string (0 = seed published, >0 = coset rep):\n");
    for (int i = 0; i < T; i++) {
        printf("%u", challenge[i]);
        if ((i + 1) % 64 == 0) printf("\n");
    }
    if (T % 64 != 0) printf("\n");
    printf("\n");
}

/* ------------------------------------------------------------------ */
int main(void)
{
    test_build_ggm();
    test_sign_verify();
    return 0;
}
