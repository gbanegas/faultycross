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
#define C 49

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
        int fault = faults[fi];
        CSPRNG_STATE_T csprng_state_fault;

        csprng_initialize(&csprng_state_fault, seed_pk, KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_pk);
        csprng_fp_mat_faulted(V_faulted, &csprng_state_fault, fault);

        char title[128];
        snprintf(title, sizeof(title), "Faulted mat (csprng_fp_mat_faulted) fault=%d, loop=%d", fault, loop);
        print_fp_mat(title, V_faulted);

        //int diff = count_differences(V_ref, V_faulted);
        printf("fault=%d / %d\n\n", fault, K * (N - K));
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

int simulate_recover_faulted(FZ_ELEM * res, sk_t * sk, pk_t * pk, char * msg, uint64_t mlen, uint16_t x_1, uint16_t x_2, FP_ELEM delta_val){
    CROSS_sig_t sig;

    FP_ELEM delta_mat [K][N-K] = {0};
    delta_mat[x_1][x_2] = delta_val;
                    
    CROSS_sign_faulted(sk, msg, mlen, delta_mat, &sig);
    
    FZ_ELEM e_hat [N];

    if (recover(e_hat, pk, msg, mlen, &sig)){
        //printf("Successfully recovered e[%d] = %d\n", x_1, e_hat[x_1]);
        res[x_1] = e_hat[x_1];
        return 1;
    } 

    return 0;
    
}


int simulate_recover_faulted_easy(FZ_ELEM * res, sk_t * sk, pk_t * pk, char * msg, uint64_t mlen, uint16_t x_1, uint16_t x_2, FP_ELEM delta_val){
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

void simulate_recover_full(int easy){

    sk_t sk;
    pk_t pk;
    char * msg = "Hello World!";
    CROSS_keygen(&sk, &pk);
    srand( time( NULL ));
    FZ_ELEM e [N] = {0};
    uint8_t recovered [N] = {0};
    int found = 0;
    int tries = 0;
    while (found < K){
        int x_1 = rand()%K;
        int x_2 = rand()%(N-K);
        FP_ELEM delta_val = rand()%P;
        //printf("Testing with V[%d][%d]=%d\n", x_1, x_2, delta_val);
        int sim = 0;
        if (easy){
            sim = simulate_recover_faulted_easy(e,&sk,&pk,msg,12,x_1,x_2,delta_val);
        } else {
            sim = simulate_recover_faulted(e,&sk,&pk,msg,12,x_1,x_2,delta_val);
        }
        if(sim){
            //printf("recovered e[%d]=%d\n", x_1, e[x_1]);
            if (!recovered[x_1]){
                recovered[x_1] = 1;
                //printf("Found %d/%d\n", found, K);
                //print_fp_vec("found", recovered, K);
                found++;
            }
        }
        tries++;
    }

    CROSS_sig_t sig;
                    
    CROSS_sign(&sk, msg, 12, &sig);
    recover_systemic_part(e, &pk);

    print_restr_vec("e_hat", e, N);
    printf("tries : %d\n", tries);

}



int main(void) {

    simulate_recover_full(1);
    
    return 0;
}
