#ifndef _GFVEC_H_
#define _GFVEC_H_

#ifdef  __cplusplus
extern  "C" {
#endif


#include "preon_settings.h"

#if 192 == GF_BITS
#include "gf2192.h"
#else
error : no gf implementation
#endif

///////////////////////////////// GF ARRAY //////////////////////////////


typedef struct gf_array {
    uint64_t * sto;
    uint64_t * vec[GF_EXT_DEG];
    unsigned len;
    unsigned _stosize_u64;
} gfvec_t;


int gfvec_alloc( gfvec_t *v, unsigned len );

void gfvec_free( gfvec_t *v);

//////////////////////////////////////////////

#include <stddef.h>

static inline
gfvec_t gfvec_slice(gfvec_t src, unsigned st_idx, unsigned len ) {
    gfvec_t r;
    r._stosize_u64 = 0;
    r.sto = NULL;
    r.len = len;
    for(unsigned j=0;j<GF_EXT_DEG;j++) r.vec[j] = src.vec[j]+st_idx;
    return r;
}

static inline
void gfvec_to_u64vec( uint64_t* dest, const gfvec_t src ) {
    for(unsigned i=0;i<src.len;i++) {
        for(int j=0;j<GF_EXT_DEG;j++) dest[j]=src.vec[j][i];
        dest += GF_EXT_DEG;
    }
}

static inline
void gfvec_from_u64vec( gfvec_t dest, const uint64_t* src ) {
    for(unsigned i=0;i<dest.len;i++) {
        for(int j=0;j<GF_EXT_DEG;j++) dest.vec[j][i]=src[j];
        src += GF_EXT_DEG;
    }
}

/////////////////////////////////////////////


void gfvec_mul_scalar( gfvec_t vec, const uint64_t * gf );

void gfvec_frildt_reduce( gfvec_t *polyx2, const uint64_t *xi );

void gfvec_fft( gfvec_t dest, const gfvec_t src , uint64_t shift );

void gfvec_ifft( gfvec_t dest, const gfvec_t src , uint64_t shift );

void gfvec_ibtfy_1stage( gfvec_t vec, uint64_t shift );



//////////////////////////////////////////////
// debug

#include "stdio.h"
static inline
void gfvec_dump( const unsigned char * s, gfvec_t vec , unsigned idx ) {
    printf("%s : [%d/%d] %llx\n", s , idx , vec.len , vec.vec[0][idx] );
}



#ifdef  __cplusplus
}
#endif

#endif
