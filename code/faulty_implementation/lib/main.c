#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#ifndef RSDP
#define RSDP
#endif
#ifndef CATEGORY_1
#define CATEGORY_1
#endif

#include "parameters.h"
#include "csprng_hash.h"
#include "CROSS.h"
#include "utils.h"

static int simulate_faulted_V(){
    uint8_t seed_pk[KEYPAIR_SEED_LENGTH_BYTES];
    for (size_t i = 0; i < KEYPAIR_SEED_LENGTH_BYTES; i++) {
        seed_pk[i] = (uint8_t)(0xA5 ^ i);
    }

    FP_ELEM V_ref[K][N-K];
    FP_ELEM V_faulted[K][N-K];

    CSPRNG_STATE_T csprng_state;
    const uint16_t dsc_csprng_seed_pk = CSPRNG_DOMAIN_SEP_CONST + (3 * T + 2);

    csprng_initialize(&csprng_state, seed_pk, KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_pk);
    csprng_fp_mat(V_ref, &csprng_state);
    //print_fp_mat("Reference mat (csprng_fp_mat)", V_ref);

    int faults[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    const int nb_faults = sizeof(faults) / sizeof(faults[0]);

    for (int fi = 0; fi < nb_faults; fi++) {
        for (int loop = 0; loop < 10; loop++){
            int fault = faults[fi];
            CSPRNG_STATE_T csprng_state_fault;

            csprng_initialize(&csprng_state_fault, seed_pk, KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_pk);
            csprng_fp_mat_faulted(V_faulted, &csprng_state_fault, fault, loop);

            char title[128];
            snprintf(title, sizeof(title), "Faulted mat (csprng_fp_mat_faulted) fault=%d, loop=%d", fault, loop);
            print_fp_mat(title, V_faulted);

            //int diff = count_differences(V_ref, V_faulted);
            printf("fault=%d / %d\n\n", fault, K * (N - K));
        }
    }

    return 0;

}

int simulate_verification(){
    sk_t sk;
    pk_t pk;
    char * msg = "Hello World!";
    CROSS_sig_t sig;
    CROSS_keygen(&sk, &pk);
    CROSS_sign(&sk, msg, 12, &sig);
    if (CROSS_verify(&pk,msg,12,&sig)){
        printf("signature verified");
        return 1;
    }
    printf("incorrect signature");
    return 0;
    
}

int simulate_verification_faulted(FZ_ELEM * res, sk_t * sk, pk_t * pk, char * msg, uint64_t mlen, uint16_t x_1, uint16_t x_2, FP_ELEM delta_val){
    CROSS_sig_t sig;

    FP_ELEM delta_mat [K][N-K] = {0};
    delta_mat[x_1][x_2] = delta_val;
                    
    CROSS_sign_faulted(sk, msg, mlen, delta_mat, &sig);
    
    FZ_ELEM e_hat [N];

    if (recover_H(e_hat, pk, msg, mlen, &sig, x_1, x_2, delta_val)){
        //printf("Successfully recovered e[%d] = %d\n", x_1, e_hat[x_1]);
        res[x_1] = e_hat[x_1];
        return 1;
    } 

    return 0;
    
}


int main(void) {

    sk_t sk;
    pk_t pk;
    char * msg = "Hello World!";
    CROSS_keygen(&sk, &pk);

    uint16_t x_1 = 0;
    FZ_ELEM res [N] = {0};
    while (x_1 < K){
        int found_x_1 = 0;
        uint16_t x_2 = 0;
        while (!found_x_1 && x_2 < N-K){
            //printf("(%d,%d)\n",x_1,x_2);
            FP_ELEM delta_val = 1;
            while (!found_x_1 && delta_val < P){
                found_x_1 = found_x_1 || simulate_verification_faulted(res, &sk, &pk, msg, 12, x_1, x_2, delta_val);
                delta_val++;
            }
            x_2++;
        }
        x_1 ++;
    } 

    print_restr_vec("e^", res, N);

    return 0;
}
