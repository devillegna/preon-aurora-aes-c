#ifndef _UTILS_PRNG_H_
#define _UTILS_PRNG_H_

#ifdef  __cplusplus
extern  "C" {
#endif

#define _DEBUG_PRNG_

#include "utils_hash.h"

#if defined(_UTILS_OPENSSL_)

#if defined(_DEBUG_PRNG_)

void randombytes( unsigned char * v , unsigned len );

#else 

#include <openssl/rand.h>

static inline
void randombytes( unsigned char * v , unsigned len ) { RAND_bytes(v, len); }

#endif


#else

#include "stdlib.h"

static inline
void randombytes( unsigned char * v , unsigned len ) { for(unsigned i=0;i<len;i++) v[i]=rand()&0xff; }

#endif



#ifdef  __cplusplus
}
#endif

#endif

