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
    uint64_t * vec[GF_EXT_DEG];
    unsigned len;
} gfvec_t;


int gfvec_alloc( gfvec_t *v, unsigned len );

void gfvec_free( gfvec_t *v);

static inline
void gfvec_to_consecutive_form( gfvec_t dest, const gfvec_t src ) {
    uint64_t *ptr = dest.vec[0];
    for(unsigned i=0;i<src.len;i++) {
        for(int j=0;j<GF_EXT_DEG;j++) ptr[j]=src.vec[j][i];
        ptr += GF_EXT_DEG;
    }
}

void gfvec_fft( gfvec_t dest, const gfvec_t src , uint64_t shift );

void gfvec_ibtfy_1stage( gfvec_t vec, uint64_t shift );



#ifdef  __cplusplus
}
#endif

#endif
