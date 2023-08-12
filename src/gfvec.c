#include "gf2192.h"


#include "stdlib.h"


//typedef struct gf_array {
//    unsigned len;
//    uint64_t * vec[GF_EXT_DEG];
//} gfvec_t;

int gfvec_alloc( gfvec_t *v, unsigned len )
{
    uint64_t * buffer = (uint64_t*) malloc( len*sizeof(uint64_t)*GF_EXT_DEG );
    if( NULL==buffer ) return -1;

    v->len = len;
    for(int i=0;i<GF_EXT_DEG;i++) {
        v->vec[i] = buffer;
        buffer += len;
    }
    return 0;
}

void gfvec_free( gfvec_t *v)
{
    free( v->vec[0] );

    v->len = 0;
    for(int i=0;i<GF_EXT_DEG;i++) v->vec[i]=NULL;
}

#include "btfy.h"

static inline int _log2( unsigned num ) { return __builtin_ctz(num); }


#include "stdio.h"
#include "stdlib.h"
#include "string.h"

void gfvec_fft( gfvec_t dest, const gfvec_t src , uint64_t shift )
{
    if(0!=(src.len&(src.len-1))) { printf("src fft size != 2^??\n"); abort(); }
    if(0!=(dest.len&(dest.len-1))) { printf("dest fft size != 2^??\n"); abort(); }
    if(0==src.len) { printf("src fft([0])\n"); abort(); }

    unsigned log_plen = (unsigned) _log2(src.len);
    for(int k=0;k<GF_EXT_DEG;k++) {
        for(unsigned i=0;i<dest.len;i+=src.len){
            memmove(&dest.vec[k][i],src.vec[k],src.len*sizeof(uint64_t));
            btfy_64( &dest.vec[k][i] , log_plen , shift+i );
        }
    }
}

void gfvec_ibtfy_1stage( gfvec_t vec, uint64_t shift )
{
    if(0==vec.len) { printf("src fft([0])\n"); abort(); }
    if(0==(vec.len&1)) { printf("src fft([odd num])\n"); abort(); }

    for(int k=0;k<GF_EXT_DEG;k++) {
        for(unsigned i=0;i<vec.len;i+=2){
            ibtfy_64( &vec.vec[k][i] , 1 , shift+i );
        }
    }


}


