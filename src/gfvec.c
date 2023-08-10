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

