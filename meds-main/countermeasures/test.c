#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "randombytes.h"

#include "params.h"
#include "api.h"
#include "meds.h"
#include "recover.h"

double osfreq(void);

long long cpucycles(void)
{
  unsigned long long result;
  asm volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
      : "=a" (result) ::  "%rdx");
  return result;
}

int main(int argc, char *argv[])
{
  printf("paramter set: %s\n\n", MEDS_name);

  long long time = 0;
  long long keygen_time = 0xfffffffffffffff;
  long long sign_time = 0xfffffffffffffff;
  long long sign_time_c1 = 0xfffffffffffffff;
  long long sign_time_c2 = 0xfffffffffffffff;
  long long verify_time = 0xfffffffffffffff;

  int rounds = 1;

  if (argc > 1)
    rounds = atoi(argv[1]);

  unsigned char entropy_input[48] = {0};

  randombytes_init(entropy_input, NULL, 256);

  char msg[4] = "Test";

  printf("pk:  %i bytes\n", CRYPTO_PUBLICKEYBYTES);
  printf("sk:  %i bytes\n", CRYPTO_SECRETKEYBYTES);
  printf("sig: %i bytes\n", CRYPTO_BYTES);
  printf("\n");

  for (int round = 0; round < rounds; round++)
  {
    uint8_t sk[CRYPTO_SECRETKEYBYTES] = {0};
    uint8_t pk[CRYPTO_PUBLICKEYBYTES] = {0};

    time = -cpucycles();
    crypto_sign_keypair(pk, sk);
    time += cpucycles();

    if (time < keygen_time) keygen_time = time;

    uint8_t sig[CRYPTO_BYTES + sizeof(msg)] = {0};
    unsigned long long sig_len = sizeof(sig);

    time = -cpucycles();
    crypto_sign(sig, &sig_len, (const unsigned char *)msg, sizeof(msg), sk);
    time += cpucycles();

    if (time < sign_time) sign_time = time;

    uint8_t sig_c1[CRYPTO_BYTES + sizeof(msg)] = {0};
    unsigned long long sig_c1_len = sizeof(sig_c1);

    time = -cpucycles();
    crypto_sign(sig_c1, &sig_c1_len, (const unsigned char *)msg, sizeof(msg), sk);
    time += cpucycles();

    if (time < sign_time_c1) sign_time_c1 = time;

    uint8_t sig_c2[CRYPTO_BYTES + sizeof(msg)] = {0};
    unsigned long long sig_c2_len = sizeof(sig_c2);

    time = -cpucycles();
    crypto_sign(sig_c2, &sig_c2_len, (const unsigned char *)msg, sizeof(msg), sk);
    time += cpucycles();

    if (time < sign_time_c2) sign_time_c2 = time;


    unsigned char msg_out[4];
    unsigned long long msg_out_len = sizeof(msg_out);

    time = -cpucycles();
    int ret = crypto_sign_open(msg_out, &msg_out_len, sig, sizeof(sig), pk);
    time += cpucycles();

    if (time < verify_time) verify_time = time;

    if (ret == 0)
      printf("success\n");
    else
      printf("!!! FAILED !!!\n");
  }

  double freq = osfreq();

  printf("\n");
  printf("Time (min of %i runs):\n", rounds);
  printf("keygen: %f   (%llu cycles)\n", keygen_time / freq, keygen_time);
  printf("sign:   %f   (%llu cycles)\n", sign_time / freq, sign_time);
  printf("sign_c1:   %f   (%llu cycles)\n", sign_time_c1 / freq, sign_time_c1);
  printf("sign_c2:   %f   (%llu cycles)\n", sign_time_c2 / freq, sign_time_c2);
  printf("verify: %f   (%llu cycles)\n", verify_time / freq, verify_time);

  return 0;
}

