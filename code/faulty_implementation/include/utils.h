#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "parameters.h"
#include "csprng_hash.h"

void print_fp_mat(const char *title, FP_ELEM A[K][N-K]);
void print_restr_vec(const char *title, FZ_ELEM * v, int size);
void print_digest(uint8_t * digest);
void print_fp_vec(const char *title, FP_ELEM * v, int size);
