#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#include "randombytes.h"
#include "hal.h"


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



int main(void) 
{

	

	hal_send_str("====== START ======");

	hal_send_str("====== END ======");

	return 0;
}
