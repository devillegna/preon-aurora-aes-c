
#include "merkeltreecommit.h"

#include "stdlib.h"

// typedef struct merkeltree {
//   size_t num_mesg;
//   uint8_t * root;
//   uint8_t * randomness;
//   uint8_t * leaves;
// } mt_t;

int mt_init( mt_t * tree , unsigned num_mesg )
{
    if (0==num_mesg) { return -1; }
    if (num_mesg&(num_mesg-1)) { return -1; }
    uint8_t * buffer = (uint8_t*) malloc( num_mesg*MT_RAND_LEN + (num_mesg*2-1)*HASH_DIGEST_LEN );
    if (NULL==buffer) { return -1; }

    tree->randomness = buffer;
    tree->leaves     = buffer + num_mesg*MT_RAND_LEN;
    tree->root       = buffer + num_mesg*MT_RAND_LEN + (num_mesg*2-2)*HASH_DIGEST_LEN;
    tree->num_mesg   = num_mesg;

    return 0;
}

void mt_free( mt_t * tree )
{
    free( tree->randomness );
    tree->randomness = NULL;
    tree->leaves   = NULL;
    tree->root     = NULL;
    tree->num_mesg = 0;
}


/*
def commit( msgList ):
    num = len(msgList)
    assert( 2 <= num )
    assert( 0==(num&(num-1)) )   # len(msgList) is a power of 2
    r = [ utrd.randombytes( LAMBDA//8 ) for i in range(num) ]
    mktree = [ [ G.sha3_256( msgList[i]+r[i] ).digest() for i in range(num) ]  ]
    while( num > 2 ):
        last_layer = mktree[-1]
        mktree.append([ G.sha3_256( last_layer[i*2]+last_layer[i*2+1] ).digest() for i in range(num>>1) ])
        num = num//2
    last_layer = mktree[-1]
    rt = G.sha3_256( b''.join([last_layer[0],last_layer[1]]) ).digest()
    return rt, r , mktree
*/

#include "randombytes.h"

int mt_commit( mt_t tree , const uint8_t * mesgs , unsigned mesg_len , unsigned num_mesg )
{
    if( tree.num_mesg != num_mesg ) { return -1; }

    randombytes( tree.randomness , num_mesg*MT_RAND_LEN );

    uint8_t *ptr = tree.leaves;
    for(unsigned i=0;i<num_mesg;i++) {
        hash_2mesg( ptr , mesgs+i*mesg_len , mesg_len , (tree.randomness) + i*MT_RAND_LEN , MT_RAND_LEN );
        ptr += HASH_DIGEST_LEN;
    }

    uint8_t * prev_l = tree.leaves;
    while( 1 < num_mesg ) {
        for(unsigned i=0;i<num_mesg;i+=2) {
            hash_1mesg( ptr , prev_l+i*HASH_DIGEST_LEN , HASH_DIGEST_LEN*2 );
            ptr += HASH_DIGEST_LEN;
        }
        prev_l += num_mesg*HASH_DIGEST_LEN;
        num_mesg >>= 1;
    }
    //if( tree->root != (ptr-HASH_DIGEST_LEN) ) return -1;  // for debug only.

    return 0;
}


/*
def open( msg , idx , r , mktree ):
    _idx = idx
    auth_path = [ msg , r[idx] ]
    for layer in mktree :
        auth_path.append( layer[idx^1] )
        idx = idx//2
    return auth_path
*/

#include "string.h"

void mt_open( uint8_t * auth_path, const mt_t tree , const uint8_t *mesg , unsigned mesg_len , unsigned mesg_idx )
{
    memmove( auth_path , mesg , mesg_len );
    auth_path += mesg_len;
    memmove( auth_path , (tree.randomness)+mesg_idx*MT_RAND_LEN , MT_RAND_LEN );
    auth_path += MT_RAND_LEN;

    size_t num_mesg = tree.num_mesg;
    uint8_t * l_start = tree.leaves;
    while( 1 < num_mesg ) {
        memmove( auth_path , l_start + (mesg_idx^1)*HASH_DIGEST_LEN , HASH_DIGEST_LEN );
        l_start   += HASH_DIGEST_LEN*num_mesg;
        auth_path += HASH_DIGEST_LEN;
        mesg_idx >>= 1;
        num_mesg >>= 1;
    }
}


/*
def verify( rt , idx , auth_path ):
    state = G.sha3_256( auth_path[0]+auth_path[1] ).digest()
    for i in range(2,len(auth_path)):
        if (idx&1) : state = G.sha3_256( auth_path[i]+state ).digest()
        else       : state = G.sha3_256( state+auth_path[i] ).digest()
        idx = idx//2
    return state == rt


*/

int mt_verify( const uint8_t * root , const uint8_t * auth_path , unsigned mesg_len , unsigned num_mesg , unsigned idx )
{
    uint8_t state[HASH_DIGEST_LEN];
    hash_1mesg( state , auth_path , mesg_len + MT_RAND_LEN );
    auth_path += mesg_len + MT_RAND_LEN;

    while( 1<num_mesg ) {
        if (idx&1) { hash_2mesg( state , auth_path , HASH_DIGEST_LEN , state , HASH_DIGEST_LEN ); }
        else       { hash_2mesg( state , state , HASH_DIGEST_LEN , auth_path , HASH_DIGEST_LEN ); }
        auth_path += HASH_DIGEST_LEN;
        idx >>= 1;
        num_mesg >>= 1;
    }

    uint8_t diff=0;
    for(int i=0;i<HASH_DIGEST_LEN;i++){ diff |= root[i]^state[i]; }
    return (0==diff);
}
