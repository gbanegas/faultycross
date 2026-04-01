#ifndef HAL_H
#define HAL_H

#include <stdint.h>
#include <stdlib.h>

enum clock_mode {
    CLOCK_FAST,
    CLOCK_BENCHMARK
};

void hal_setup(const enum clock_mode clock);
void hal_send_str(const char* in);
void hal_send_bytes(const uint8_t* data, size_t len);
uint64_t hal_get_time(void);
size_t hal_get_stack_size(void);

#endif
