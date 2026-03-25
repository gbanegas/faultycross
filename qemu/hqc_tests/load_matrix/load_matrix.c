#include <stdio.h>
#include <stdint.h>

#define K 76
#define N 127
#define FP_ELEM uint8_t

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


// Function to load the matrix from a binary file
void load_matrix(const char* filename, FP_ELEM matrix[K][N-K]) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        perror("Failed to open file");
        return;
    }
    size_t elements_read = fread(matrix, sizeof(FP_ELEM), K * (N - K), f);
    if (elements_read != K * (N - K)) {
        fprintf(stderr, "Failed to read all data: read %zu elements\n", elements_read);
    }
    fclose(f);
}

// Example usage
int main() {
    FP_ELEM loaded_matrix[K][N-K];
    load_matrix("matrix.bin", loaded_matrix);
    print_fp_mat("loaded:", loaded_matrix);
    // Now you can use loaded_matrix
    return 0;
}