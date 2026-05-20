#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

#include "fips202.h"

#include "params.h"

#include "api.h"
#include "randombytes.h"

#include "meds.h"

#include "seed.h"
#include "util.h"
#include "bitstream.h"

#include "matrixmod.h"

#define CEILING(x,y) (((x) + (y) - 1) / (y))


// Assuming sm_prime is a successfully faulted signature, recover one or more A_i 
// if x == -1, try to recover all A_i such that h[i] > 0
// else only A_x
int recover(
    unsigned char *m, 
    unsigned long long *mlen,
    const unsigned char *sm_prime, 
    unsigned long long smlen_prime,
    const unsigned char *pk,
    int x
  )
{
  //x = 1;
  LOG_HEX(pk, MEDS_PK_BYTES);
  LOG_HEX(sm_prime, smlen_prime);

  pmod_mat_t G_data[MEDS_k*MEDS_m*MEDS_n * MEDS_s];
  pmod_mat_t *G[MEDS_s];

  for (int i = 0; i < MEDS_s; i++)
    G[i] = &G_data[i * MEDS_k * MEDS_m * MEDS_n];


  rnd_sys_mat(G[0], MEDS_k, MEDS_m*MEDS_n, pk, MEDS_pub_seed_bytes);

  {
    bitstream_t bs;

    bs_init(&bs, (uint8_t*)pk + MEDS_pub_seed_bytes, MEDS_PK_BYTES - MEDS_pub_seed_bytes);

    for (int i = 1; i < MEDS_s; i++)
    {
      for (int r = 0; r < MEDS_k; r++)
        for (int c = 0; c < MEDS_k; c++)
          if (r == c)
            pmod_mat_set_entry(G[i], MEDS_k, MEDS_m * MEDS_n, r, c, 1);
          else
            pmod_mat_set_entry(G[i], MEDS_k, MEDS_m * MEDS_n, r, c, 0);

      for (int j = (MEDS_m-1)*MEDS_n; j < MEDS_m*MEDS_n; j++)
        G[i][MEDS_m*MEDS_n + j] = bs_read(&bs, GFq_bits);

      for (int r = 2; r < MEDS_k; r++)
        for (int j = MEDS_k; j < MEDS_m*MEDS_n; j++)
          G[i][r*MEDS_m*MEDS_n + j] = bs_read(&bs, GFq_bits);

      for (int ii = 0; ii < MEDS_m; ii++)
        for (int j = 0; j < MEDS_n; j++)
          G[i][ii*MEDS_n + j] = ii == j ? 1 : 0;

      for (int ii = 0; ii < MEDS_m-1; ii++)
        for (int j = 0; j < MEDS_n; j++)
          G[i][MEDS_m*MEDS_n + ii*MEDS_n + j] = (ii+1) == j ? 1 : 0;

      bs_finalize(&bs);
    }
  }

  for (int i = 0; i < MEDS_s; i++)
    LOG_MAT_FMT(G[i], MEDS_k, MEDS_m*MEDS_n, "G[%i]", i);
 
  LOG_HEX_FMT(sm_prime, MEDS_w * (CEILING(MEDS_m*MEDS_m * GFq_bits, 8) + CEILING(MEDS_n*MEDS_n * GFq_bits, 8)), "munu");
  LOG_HEX_FMT(sm_prime + MEDS_w * (CEILING(MEDS_m*MEDS_m * GFq_bits, 8) + CEILING(MEDS_n*MEDS_n * GFq_bits, 8)),
      MEDS_max_path_len * MEDS_st_seed_bytes, "path");

  uint8_t *digest = (uint8_t*)sm_prime + (MEDS_SIG_BYTES - MEDS_digest_bytes - MEDS_st_salt_bytes);

  uint8_t *alpha = (uint8_t*)sm_prime + (MEDS_SIG_BYTES - MEDS_st_salt_bytes);

  LOG_HEX(digest, MEDS_digest_bytes);
  LOG_HEX(alpha, MEDS_st_salt_bytes);

  uint8_t h[MEDS_t];

  parse_hash(digest, MEDS_digest_bytes, h, MEDS_t);


  bitstream_t bs;

  bs_init(&bs, (uint8_t*)sm_prime, MEDS_w * (CEILING(MEDS_m*MEDS_m * GFq_bits, 8) + CEILING(MEDS_n*MEDS_n * GFq_bits, 8)));

  uint8_t *faulted_path = (uint8_t*)sm_prime + MEDS_w * (CEILING(MEDS_m*MEDS_m * GFq_bits, 8) + CEILING(MEDS_n*MEDS_n * GFq_bits, 8));

  uint8_t faulted_stree[MEDS_st_seed_bytes * SEED_TREE_size] = {0};

  path_to_stree_faulted(faulted_stree, h, faulted_path, alpha, x);

  printf("Faulted tree: ");
  print_tree(faulted_stree);


  uint8_t *sigma = &faulted_stree[MEDS_st_seed_bytes * SEED_TREE_ADDR(MEDS_seed_tree_height, 0)];

  pmod_mat_t G_hat_i[MEDS_k*MEDS_m*MEDS_n];

  pmod_mat_t mu[MEDS_m*MEDS_m];
  pmod_mat_t nu[MEDS_n*MEDS_n];


  uint8_t seed_buf[MEDS_st_salt_bytes + MEDS_st_seed_bytes + sizeof(uint32_t)] = {0};
  memcpy(seed_buf, alpha, MEDS_st_salt_bytes);

  uint8_t *addr_pos = seed_buf + MEDS_st_salt_bytes + MEDS_st_seed_bytes;


  keccak_state shake;
  shake256_init(&shake);

  for (int i = 0; i < MEDS_t; i++)
  {
    if (h[i] > 0)
    {
        for (int j = 0; j < MEDS_m*MEDS_m; j++)
        mu[j] = bs_read(&bs, GFq_bits) % MEDS_p;

        bs_finalize(&bs);

        for (int j = 0; j < MEDS_n*MEDS_n; j++)
        nu[j] = bs_read(&bs, GFq_bits) % MEDS_p;

        bs_finalize(&bs);


        LOG_MAT_FMT(mu, MEDS_m, MEDS_m, "mu[%i]", i);
        LOG_MAT_FMT(nu, MEDS_n, MEDS_n, "nu[%i]", i);

        // Check if mu is invetible.
        {
        pmod_mat_t tmp_mu[MEDS_m*MEDS_m];

        memcpy(tmp_mu, mu, MEDS_m*MEDS_m*sizeof(GFq_t));

        if (pmod_mat_syst_ct(tmp_mu, MEDS_m, MEDS_m) != 0)
        {
            fprintf(stderr, "Signature verification failed; malformed signature!\n");

            return -1;
        }
        }

        // Check if nu is invetible.
        {
        pmod_mat_t tmp_nu[MEDS_n*MEDS_n];

        memcpy(tmp_nu, nu, MEDS_n*MEDS_n*sizeof(GFq_t));

        if (pmod_mat_syst_ct(tmp_nu, MEDS_n, MEDS_n) != 0)
        {
            fprintf(stderr, "Signature verification failed; malformed signature!\n");

            return -1;
        }
        }


        pi(G_hat_i, mu, nu, G[h[i]]);


        LOG_MAT_FMT(G_hat_i, MEDS_k, MEDS_m*MEDS_n, "G_hat[%i]", i);

        if (pmod_mat_syst_ct(G_hat_i, MEDS_k, MEDS_m*MEDS_n) < 0)
        {
        fprintf(stderr, "Signature verification failed!\n");

        return -1;
        }

        LOG_MAT_FMT(G_hat_i, MEDS_k, MEDS_m*MEDS_n, "G_hat[%i]", i);

        pmod_mat_t A_hat_i[MEDS_m*MEDS_m];
        pmod_mat_t B_hat_i[MEDS_n*MEDS_n];
        while (1 == 1)
        {
            LOG_VEC_FMT(&sigma[i*MEDS_st_seed_bytes], MEDS_st_seed_bytes, "seeds[%i]", i);
            uint8_t sigma_A_hat_i[MEDS_pub_seed_bytes];
            uint8_t sigma_B_hat_i[MEDS_pub_seed_bytes];

            for (int j = 0; j < 4; j++)
                addr_pos[j] = (i >> (j*8)) & 0xff;

            memcpy(seed_buf + MEDS_st_salt_bytes, &sigma[i*MEDS_st_seed_bytes], MEDS_st_seed_bytes);

            LOG_HEX_FMT(seed_buf, MEDS_st_salt_bytes + MEDS_st_seed_bytes + 4, "sigma_prime[%i]", i);

            XOF((uint8_t*[]){sigma_A_hat_i, sigma_B_hat_i, &sigma[i*MEDS_st_seed_bytes]},
                (size_t[]){MEDS_pub_seed_bytes, MEDS_pub_seed_bytes, MEDS_st_seed_bytes},
                seed_buf, MEDS_st_salt_bytes + MEDS_st_seed_bytes + 4,
                3);


            LOG_HEX_FMT(sigma_A_hat_i, MEDS_pub_seed_bytes, "sigma_A_hat[%i]", i);
            rnd_inv_matrix(A_hat_i, MEDS_m, MEDS_m, sigma_A_hat_i, MEDS_pub_seed_bytes);

            LOG_HEX_FMT(sigma_B_hat_i, MEDS_pub_seed_bytes, "sigma_B_hat[%i]", i);
            rnd_inv_matrix(B_hat_i, MEDS_n, MEDS_n, sigma_B_hat_i, MEDS_pub_seed_bytes);

            LOG_MAT_FMT(A_hat_i, MEDS_m, MEDS_m, "A_hat[%i]", i);
            LOG_MAT_FMT(B_hat_i, MEDS_n, MEDS_n, "B_hat[%i]", i);

            LOG_MAT_FMT(G_hat_i, MEDS_k, MEDS_m*MEDS_n, "G_hat[%i]", i);

            if (pmod_mat_syst_ct(G_hat_i, MEDS_k, MEDS_m*MEDS_n) == 0)
            {
            LOG_MAT_FMT(G_hat_i, MEDS_k, MEDS_m*MEDS_n, "G_hat[%i]", i);
            break;
            }

          }
        

        if (x<0 || i==x) {

          pmod_mat_t A_i[MEDS_m*MEDS_m]={0};
          pmod_mat_inv(A_i, A_hat_i, MEDS_m, MEDS_m);
          pmod_mat_mul(A_i, MEDS_m, MEDS_m, A_i, MEDS_m, MEDS_m, mu, MEDS_m, MEDS_m);
          printf("Found A_inv_%d :\n",i);
          pmod_mat_print(A_i, MEDS_m, MEDS_m);

          pmod_mat_t B_i[MEDS_n*MEDS_n]={0};
          pmod_mat_inv(B_i, B_hat_i, MEDS_n, MEDS_n);
          pmod_mat_mul(B_i, MEDS_n, MEDS_n, nu, MEDS_n, MEDS_n, B_i, MEDS_n, MEDS_n);
          printf("Found B_inv_%d :\n",i);
          pmod_mat_print(B_i, MEDS_n, MEDS_n);

        }
        

      }
    }
  
  return 0;
}

