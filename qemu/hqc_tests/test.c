#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#include "randombytes.h"
#include "hal.h"
#include "parameters.h"
#include "csprng_hash.h"


static void fill_message(uint8_t *m, size_t mlen) {
	for (size_t i = 0; i < mlen; i++) {
		m[i] = (uint8_t) i;
	}
}

static void print_bytes_dec(const char *label, const uint8_t *buf, size_t len) {
	char out[256];
	size_t pos = 0;

	// Optional label
	if (label) {
		pos += snprintf(out + pos, sizeof(out) - pos, "%s", label);
	}

	for (size_t i = 0; i < len; i++) {
		// If we’re close to the end of the buffer, flush
		if (pos > sizeof(out) - 8) {
			out[pos] = '\0';
			hal_send_str(out);
			pos = 0;
		}
		pos += snprintf(out + pos, sizeof(out) - pos, "%u,", buf[i]);
	}

	// Add newline and flush remaining
	if (pos > sizeof(out) - 4) {
		out[pos] = '\0';
		hal_send_str(out);
		pos = 0;
	}
	pos += snprintf(out + pos, sizeof(out) - pos, "\n");
	out[pos] = '\0';
	hal_send_str(out);
}

static void hal_sendf(const char *fmt, ...)
{
    char buf[128];  // increase if you want longer lines
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    hal_send_str(buf);   // hal_send_str adds '\n' already
}


void print_fp_mat(const char *title, FP_ELEM A[K][N-K]) {
    hal_send_str(title);
    hal_send_str("\n");
    for (int i = 0; i < K; i++) {
        char row[1024];
        size_t pos = 0;
        pos += snprintf(row + pos, sizeof(row) - pos, "[%3d] ", i);
        for (int j = 0; j < N - K; j++) {
            pos += snprintf(row + pos, sizeof(row) - pos, "%3u", (unsigned)A[i][j]);
            if (j < N - K - 1) pos += snprintf(row + pos, sizeof(row) - pos, " ");
        }
        hal_send_str(row);
    }
}


int main(void) 
{


	//hal_send_str("====== START ======");
	uint8_t seed_sk[KEYPAIR_SEED_LENGTH_BYTES] = {0};
	randombytes(seed_sk,KEYPAIR_SEED_LENGTH_BYTES);
	uint8_t seed_e_seed_pk[2][KEYPAIR_SEED_LENGTH_BYTES];
	const uint16_t dsc_csprng_seed_sk = CSPRNG_DOMAIN_SEP_CONST + (3*T+1);

  	CSPRNG_STATE_T csprng_state;
  	csprng_initialize(&csprng_state, seed_sk, KEYPAIR_SEED_LENGTH_BYTES, dsc_csprng_seed_sk);
  	csprng_randombytes((uint8_t *)seed_e_seed_pk, 2*KEYPAIR_SEED_LENGTH_BYTES,&csprng_state); 	


	FP_ELEM res[K][N-K];
	csprng_fp_mat(res, &csprng_state);


	//print_fp_mat("V_tr", res);

	hal_send_bytes((uint8_t*)res, sizeof(res));

	//hal_send_str("====== END ======");

	return 0;
}
