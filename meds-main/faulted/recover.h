#ifndef RECOVER_H
#define RECOVER_H

#include "api.h"
#include "params.h"

int recover(
    unsigned char *m, 
    unsigned long long *mlen,
    const unsigned char *sm_prime, 
    unsigned long long smlen_prime,
    const unsigned char *pk,
    int x
  );

#endif

