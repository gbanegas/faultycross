#include "utils.h"

void print_fp_mat(const char *title, FP_ELEM A[K][N-K]) {
    printf("%s\n", title);
    for (int i = 0; i < K; i++) {
        printf("[%3d] ", i);
        for (int j = 0; j < N - K; j++) {
            printf("%3u", (unsigned)A[i][j]);
            if (j < N - K - 1) putchar(' ');
        }
        putchar('\n');
    }
    putchar('\n');
}

void print_restr_vec(const char *title, FZ_ELEM * v, int size) {
    printf("%s [", title);
    for (int i = 0; i < size; i++) {
        printf("%d ", v[i]);
    }
    printf("]\n");
}

void print_fp_vec(const char *title, FP_ELEM * v, int size) {
    printf("%s [", title);
    for (int i = 0; i < size; i++) {
        printf("%d ", v[i]);
    }
    printf("]\n");
}


void print_digest(uint8_t * digest){

    for (size_t i = 0; i < HASH_DIGEST_LENGTH; i++) {
        printf("%02x ", digest[i]);
    }
    printf("\n");

}
