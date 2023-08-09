#ifndef _UTILS_PRNG_H_
#define _UTILS_PRNG_H_

#ifdef  __cplusplus
extern  "C" {
#endif



#include "utils_hash.h"

#if defined(_UTILS_OPENSSL_)

#include <openssl/rand.h>

static inline
void randombytes( unsigned char * v , unsigned len ) { RAND_bytes(v, len); }

#else

#include "stdlib.h"

static inline
void randombytes( unsigned char * v , unsigned len ) { for(unsigned i=0;i<len;i++) v[i]=rand()&0xff; }

#endif



#ifdef  __cplusplus
}
#endif

#endif