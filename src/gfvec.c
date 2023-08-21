#include "gfvec.h"

#include "stdlib.h"


//typedef struct gf_array {
//    unsigned len;
//    uint64_t * vec[GF_EXT_DEG];
//} gfvec_t;

int gfvec_alloc( gfvec_t *v, unsigned len )
{
    uint64_t * buffer = (uint64_t*) malloc( len*GF_EXT_DEG*sizeof(uint64_t) );
    if( NULL==buffer ) return -1;

    v->_stosize_u64 = len*GF_EXT_DEG;
    v->len = len;
    v->sto = buffer;
    for(int i=0;i<GF_EXT_DEG;i++) {
        v->vec[i] = buffer;
        buffer += len;
    }
    return 0;
}

void gfvec_free( gfvec_t *v)
{
    if(v->_stosize_u64) free( v->sto );
    v->_stosize_u64 = 0;
    v->sto = NULL;
    v->len = 0;
    for(int i=0;i<GF_EXT_DEG;i++) v->vec[i]=NULL;
}


////////////////////////////////////////////////////

#if 24 == GF_BYTES

#include "gf2192.h"

void gfvec_mul( gfvec_t c, gfvec_t a , gfvec_t b )
{
    for(unsigned i=0;i<c.len;i++) {
        gf2192_mul( c.vec[0]+i , c.vec[1]+i , c.vec[2]+i , a.vec[0][i] , a.vec[1][i] , a.vec[2][i] , b.vec[0][i] , b.vec[1][i] , b.vec[2][i] );
    }
}

void gfvec_mul_scalar( gfvec_t vec, const uint64_t * gf )
{
    for(unsigned i=0;i<vec.len;i++) {
        gf2192_mul( vec.vec[0]+i , vec.vec[1]+i , vec.vec[2]+i , vec.vec[0][i] , vec.vec[1][i] , vec.vec[2][i] , gf[0] , gf[1] , gf[2] );
    }
}

void gfvec_frildt_reduce( gfvec_t *polyx2, const uint64_t *xi )
{
    unsigned polylen = polyx2->len/2;
    for(unsigned i=0;i<polylen;i++) {
        uint64_t t0,t1,t2;
        gf2192_mul( &t0 , &t1 , &t2 , polyx2->vec[0][1+i*2] , polyx2->vec[1][1+i*2] , polyx2->vec[2][1+i*2] , xi[0] , xi[1] , xi[2] ); // odd terms * xi
        polyx2->vec[0][i] = polyx2->vec[0][i*2]^t0;
        polyx2->vec[1][i] = polyx2->vec[1][i*2]^t1;
        polyx2->vec[2][i] = polyx2->vec[2][i*2]^t2;
    }
    polyx2->len = polylen;
}



#endif

/////////////////////////////////////////////////////



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

void gfvec_ifft( gfvec_t dest, const gfvec_t src , uint64_t shift )
{
    if(0!=(src.len&(src.len-1))) { printf("src fft size != 2^??\n"); abort(); }
    if(0!=(dest.len&(dest.len-1))) { printf("dest fft size != 2^??\n"); abort(); }
    if(0==src.len) { printf("src fft([0])\n"); abort(); }

    unsigned log_plen = (unsigned) _log2(src.len);
    for(int k=0;k<GF_EXT_DEG;k++) {
        for(unsigned i=0;i<dest.len;i+=src.len){
            memmove(&dest.vec[k][i],src.vec[k],src.len*sizeof(uint64_t));
            ibtfy_64( &dest.vec[k][i] , log_plen , shift+i );
        }
    }
}


void gfvec_ibtfy_1stage( gfvec_t vec, uint64_t shift )
{
    if(0==vec.len) { printf("ifft([0])\n"); abort(); }
    if((vec.len)&1) { printf("ifft([odd num])\n"); abort(); }

    for(int k=0;k<GF_EXT_DEG;k++) {
        for(unsigned i=0;i<vec.len;i+=2){
            ibtfy_64( &vec.vec[k][i] , 1 , shift+i );
        }
    }
}


#include "polydiv.h"

void gfvec_polydiv( gfvec_t poly , unsigned si )
{
    for(int k=0;k<GF_EXT_DEG;k++) {
        polydiv( poly.vec[k] , (int)poly.len , si );
    }
}

void gfvec_ipolydiv( gfvec_t poly , unsigned si )
{
    for(int k=0;k<GF_EXT_DEG;k++) {
        ipolydiv( poly.vec[k] , (int)poly.len , si );
    }
}


