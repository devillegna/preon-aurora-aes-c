#ifndef _GF2192_H_
#define _GF2192_H_

#ifdef  __cplusplus
extern  "C" {
#endif


#include "gf264.h"

// gf2192 := gf264[x]/(x^3+x+1)
static inline
void gf2192_mul(uint64_t *r0,uint64_t *r1,uint64_t *r2,uint64_t a0,uint64_t a1,uint64_t a2,uint64_t b0,uint64_t b1,uint64_t b2)
{
    uint64_t c0=gf264_mul(a0,b0);
    uint64_t c1=gf264_mul(a0,b1)^gf264_mul(a1,b0);
    uint64_t c2=gf264_mul(a0,b2)^gf264_mul(a1,b1)^gf264_mul(a2,b0);
    uint64_t c3=gf264_mul(a1,b2)^gf264_mul(a2,b1);
    uint64_t c4=gf264_mul(a2,b2);
    *r2 = c2^c4;
    *r1 = c1^c4^c3;
    *r0 = c0^c3;
}


#define GF_EXT_DEG    3



///////////////////////////////// GF ARRAY //////////////////////////////


typedef struct gf_array {
    unsigned len;
    uint64_t * vec[GF_EXT_DEG];
} gfvec_t;


int gfvec_alloc( gfvec_t *v, unsigned len );

void gfvec_free( gfvec_t *v);




#ifdef  __cplusplus
}
#endif

#endif