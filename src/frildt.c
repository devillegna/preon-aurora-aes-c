
#include "frildt.h"

#include "merkeltreecommit.h"

#include "string.h"


#include "utils_hash.h"

int frildt_commit_phase( uint8_t * proof , mt_t mktrees[] , gfvec_t mesgs[], gfvec_t v0 ,  unsigned poly_len , uint8_t *h_state )
{
    uint64_t xi[FRI_HASH_LEN/sizeof(uint64_t)];
    uint8_t *u8ptr_xi = (uint8_t*) xi;
    uint8_t bytes[2] = {3,1};

    uint64_t offset = FRI_RS_SHIFT;
    gfvec_t vi = v0;

    for(uint8_t i=0;i<FRI_CORE_N_COMMITS;i++) {
    //while( 2 < poly_len ) {
        //xi = gf.from_bytes( H.gen( h_state , bytes([3+i,1]) )[:gf.GF_BSIZE] )
        bytes[0] = 3+i;
        hash_2mesg( u8ptr_xi , h_state , FRI_HASH_LEN , bytes , 2 );

        //printf("iter: %d, xi: %llx\n", i , xi[0] );

        //printf("iter: %d, polylen = %d, vi.len = %d\n", i , poly_len , vi.len );
        //vi = gf.ibtfy_1( vi , offset )
        gfvec_ibtfy_1stage( vi , offset );
        //vi_e = vi[::2] //vi_o = vi[1::2] //vi = [ vi_e[j]^gf.mul(vi_o[j],xi) for j in range(len(vi_e)) ]
        gfvec_frildt_reduce( &vi , xi );

        offset   >>= 1;
        poly_len >>= 1;
        if( poly_len*FRI_RS_RHO != vi.len ) { abort(); } //assert( vi.len == poly_len*FRI_RS_RHO );
        if ( poly_len <= 2 ) break;

        //mesg = [ gf.to_bytes(vi[j]) + gf.to_bytes(vi[j+1]) for j in range(0,len(vi),2) ]
        gfvec_to_u64vec( mesgs[i].sto , vi );
        //root , randomness , tree = mt.commit( mesg )
        //mktrees.append( (root,mesg,randomness,tree) )
        //printf( "mktrees[i-1].num_mesg = %d, poly_len*FRI_RS_RHO/2 = %d\n" , mktrees[i-1].num_mesg , poly_len*FRI_RS_RHO/2 );
        if( mt_commit( mktrees[i] , (uint8_t*)mesgs[i].sto , FRI_MT_MESG_LEN , poly_len*FRI_RS_RHO/2 ) ) { return -1; }
        // mt_commit( mktrees[i-1] , (uint8_t*)mesg.sto , FRI_MT_MESG_LEN , poly_len*FRI_RS_RHO/2 )

        //commits.append( root )
        memcpy( proof , mktrees[i].root , FRI_HASH_LEN );   proof += FRI_HASH_LEN;

        //h_state = H.gen( h_state , gf.to_bytes(xi) , root )
        hash_3mesg( h_state , h_state , FRI_HASH_LEN , u8ptr_xi , FRI_GF_BYTES , mktrees[i].root , FRI_HASH_LEN );
    }
    //cc = gf.ifft( vi[:2] , 1 , offset )   # will get the same poly no matter applying ibtfy_1 to whatever pairs. 
    vi.len = 2;
    gfvec_ibtfy_1stage( vi , offset );

    //dump( "cc:" , [hex(i) for i in cc ] )
    //dump( f"open deg 1 poly: {hex(cc[0])} + x* {hex(cc[1])}" )
    //d1poly = gf.to_bytes(cc[0]) + gf.to_bytes(cc[1])
    uint64_t d1poly[2*FRI_GF_NUMU64];
    gfvec_to_u64vec( d1poly , vi );
    memcpy( proof , d1poly , 2*FRI_GF_BYTES );  proof += 2*FRI_GF_BYTES;

    //h_state = H.gen( gf.to_bytes(xi) , d1poly )
    hash_2mesg( h_state , h_state , FRI_HASH_LEN , (uint8_t*)d1poly , 2*FRI_GF_BYTES );
    //dump( f"update h_state <- H( xi || c0 || c1 ): {h_state}" )
    //return commits , d1poly , mktrees , h_state

    //printf("d1poly: %llx\n", d1poly[0] );
    //printf("h_state: %x %x %x %x\n", h_state[0], h_state[1], h_state[2], h_state[3]);

    return 0;
}




void frildt_get_queries( uint32_t * queries , const uint8_t * h_state ) {
#if FRI_N_QUERY >= 256 
FRI_N_QUERY error: QUERY overflow.
#endif
#if FRI_CORE_N_COMMITS >=253
FRI_CORE_N_COMMITS error: QUERY overflow.
#endif
    //queries = [ H.gen(h_state,bytes( [ 3+ldt_n_commit(f_length)+1 , j ] ))[:4] for j in range(1,Nq+1) ]   # use 32 bits of hash results only
    //idx_mask = (RS_rho*f_length//2)-1
    //queries = [ int.from_bytes(e,'little')&idx_mask for e in queries ]

    uint32_t h32_state[FRI_HASH_LEN/sizeof(uint32_t)];
    uint8_t bytes[2] = { 3 + FRI_CORE_N_COMMITS , 0};
    uint32_t idx_mask = FRI_MT_N_MESG - 1;
    for(uint8_t j=1;j<=FRI_N_QUERY;j++) {
        hash_2mesg( (uint8_t*)h32_state , h_state , FRI_HASH_LEN , bytes , 2 );
        queries[j-1] = h32_state[0]&idx_mask;           // XXX: endianness
    }
}



void frildt_query_phase( uint8_t * proof , mt_t mktrees[] , gfvec_t mesgs[], const uint32_t * queries ) {
    uint32_t qq[FRI_N_QUERY];
    for(int i=0;i<FRI_N_QUERY;i++) { qq[i] = queries[i]>>1; }   // skip first commit/opened mesgs

    unsigned lognmesg = FRI_MT_LOGMESG;
    for(int j=0;j<FRI_CORE_N_COMMITS;j++) {
        lognmesg -= 1;
        unsigned authpath_len = MT_AUTHPATH_LEN( FRI_MT_MESG_LEN , lognmesg );
        mt_batchopen(proof , mktrees[j] , (uint8_t*)mesgs[j].sto , FRI_MT_MESG_LEN , qq, FRI_N_QUERY );
        proof += authpath_len*FRI_N_QUERY;
        for(int i=0;i<FRI_N_QUERY;i++) {  qq[i] >>= 1; }
    }
}




int frildt_gen_proof( uint8_t * proof , const gfvec_t *f0, const uint8_t *ih_state )
{
    gfvec_t v0;
    gfvec_alloc( &v0 , FRI_POLYLEN*FRI_RS_RHO );
    gfvec_fft( v0, *f0 , FRI_RS_SHIFT);

    // first commit
    mt_t mkt;
    mt_init( &mkt , v0.len/2 );
    gfvec_t gfmesg;
    gfvec_alloc( &gfmesg , v0.len );
    gfvec_to_u64vec( gfmesg.sto , v0 );
    mt_commit( mkt , (uint8_t*)gfmesg.sto , FRI_MT_MESG_LEN , FRI_MT_N_MESG );


    frildt_proof_t ptr_proof;
    frildt_proof_setptr( &ptr_proof , proof );
    //printf("proof size: %d\n", size );
    memcpy( ptr_proof.first_commit , mkt.root , FRI_HASH_LEN );  // output first commit


    // commits the same with aurora
    uint8_t h_state[FRI_HASH_LEN];  memcpy( h_state , ih_state , FRI_HASH_LEN );
    mt_t mkts[FRI_CORE_N_COMMITS];
    for(int i=0;i<FRI_CORE_N_COMMITS;i++) { mt_init( &mkts[i] , FRI_MT_N_MESG>>(1+i) ); }  // XXX: check malloc errors
    gfvec_t mesgs[FRI_CORE_N_COMMITS];
    for(int i=0;i<FRI_CORE_N_COMMITS;i++) { gfvec_alloc( &mesgs[i] , FRI_MT_N_MESG>>(i) ); }  // XXX: check malloc errors


    if( 0 != frildt_commit_phase( ptr_proof.commits[0] , mkts, mesgs, v0 , FRI_POLYLEN , h_state ) ) { printf("fri commit phase fails.\n"); abort(); }
    // frildt_commit_phase( ptr_proof.commits[0] , mkts , v0 , FRI_POLYLEN , h_state );

    uint32_t queries[FRI_N_QUERY];
    frildt_get_queries( queries , h_state );
    //printf("query_idx: %d\n", queries[0]);

    frildt_query_phase( ptr_proof.open_mesgs[0] , mkts , mesgs , queries );
    // first opened mesgs
    mt_batchopen( ptr_proof.first_mesgs , mkt , (uint8_t*)gfmesg.sto , FRI_MT_MESG_LEN , queries , FRI_N_QUERY );  // open first commit

    for(int i=0;i<FRI_CORE_N_COMMITS;i++) { mt_free( &mkts[i] ); }
    for(int i=0;i<FRI_CORE_N_COMMITS;i++) { gfvec_free( &mesgs[i] ); }
    gfvec_free( &gfmesg );
    mt_free( &mkt );
    gfvec_free( &v0 );
    return 0;
}


//////////////////////////////////////////////////


void frildt_recover_challenges( uint32_t * queries , uint64_t *d1poly , uint64_t *xi , const uint8_t *_h_state , unsigned poly_len , const uint8_t * proof )
{
    uint8_t h_state[FRI_HASH_LEN];  memcpy(h_state,_h_state,FRI_HASH_LEN);
    uint64_t temp[FRI_HASH_LEN/sizeof(uint64_t)];
    uint8_t bytes[2] = {3,1};
    for(uint8_t i=0;i<FRI_CORE_N_COMMITS;i++) {
        bytes[0] = 3+i;
        hash_2mesg( (uint8_t*)temp , h_state , FRI_HASH_LEN , bytes , 2 );
        for(int j=0;j<FRI_GF_NUMU64;j++) xi[j]=temp[j];
        //printf("iter: %d, xi: %llx\n", i , xi[0] );

        poly_len >>= 1;
        if ( poly_len <= 2 ) break;
        hash_3mesg( h_state , h_state , FRI_HASH_LEN , (uint8_t*)xi , FRI_GF_BYTES , proof , FRI_HASH_LEN );
        xi += FRI_GF_NUMU64;
        proof += FRI_HASH_LEN;
    }
    memcpy( d1poly , proof , 2*FRI_GF_BYTES );  proof += 2*FRI_GF_BYTES;

    hash_2mesg( h_state , h_state , FRI_HASH_LEN , (uint8_t*)d1poly , 2*FRI_GF_BYTES );

    //printf("d1poly: %llx\n", d1poly[0] );
    //printf("h_state: %x %x %x %x\n", h_state[0], h_state[1], h_state[2], h_state[3]);

    frildt_get_queries( queries , h_state );
}




#if 0
def ldt_verify_proof( commits , d1poly , first_mesgs , open_mesgs , xi , queries , RS_shift=1<<63 , verbose = 1 ):
    if 1 == verbose : dump = print
    else : dump = _dummy

    dump( "#### check linear relations and opened commit ######" )
    offset = RS_shift
    j = 0
    # check first_mesgs
    if True :
        # check linear relations
        dump( f"check linear relations:" )
        mesg      = first_mesgs   # [ path[0] for path in first_mesgs ]
        next_mesg = [ path[0] for path in open_mesgs[0] ]
        verify_j  = [ _check_linear_relation(mesg[i],next_mesg[i],q,xi[j],offset) for i,q in enumerate(queries) ]
        dump( f"check linear relations:" , all(verify_j) )
        if not all(verify_j) : return False
        queries = [ q//2 for q in queries ]
        offset >>= 1
        j = j+1

    for idx,auths in enumerate(open_mesgs) :
        dump( f"open iteration: {j}" )
        dump( f"auths[{len(auths[0])}]: Nbyte: ", sum( map( len,auths[0]) ) )
        if not mt.batchverify( queries , commits[j-1] , auths ) :
            dump("batchverify() fails")
            return False
        else : dump("oepned mesgs are verified.")

        # check linear relations
        mesg = [ path[0] for path in auths ]
        if idx == len(open_mesgs)-1 : break
        dump( f"check linear relations [{idx}]:" )
        next_mesg = [ path[0] for path in open_mesgs[idx+1] ]
        verify_j  = [ _check_linear_relation(mesg[i],next_mesg[i],q,xi[j],offset) for i,q in enumerate(queries) ]
        dump( f"check linear relations [{idx}]:" , all(verify_j) )
        if not all(verify_j) : return False
        queries = [ q//2 for q in queries ]
        offset >>= 1
        j = j+1
    # check deg 1 poly
    verify_j = [ _check_deg1poly_linear_relation(mesg[i],d1poly,q,xi[-1],offset) for i,q in enumerate(queries) ]
    dump( f"check last linear relations (with the d1poly):" , all(verify_j) )
    if not all(verify_j) : return False
    return True

def _check_linear_relation( mesgj1 , mesgj0 , idx , xi , offset ) :
    new_j0 = gf.from_bytes_x2( mesgj0 )
    org_j1 = gf.from_bytes_x2( mesgj1 )
    org_j0 = gf.ibtfy_1( org_j1 , offset^(idx<<1) )
    cc1 = org_j0[0] ^ gf.mul( org_j0[1] , xi )
    return new_j0[idx&1] == cc1

def _check_deg1poly_linear_relation( mesgjm1 , d1poly , idx , xi , offset ) :
    m0 = gf.fft( gf.from_bytes_x2(d1poly) , 1 , (offset>>1)^(idx^(idx&1)) )
    return _check_linear_relation( mesgjm1 , gf.to_bytes(m0[0])+gf.to_bytes(m0[1]) , idx , xi , offset )
#endif

#if 0
def ldt_verify( proof , _poly_len , h_state , Nq = 26 , RS_rho = 8 , verbose = 1 ):
    n_commits = ldt_n_commit( _poly_len )
    first_commit = proof[0]
    commits     = proof[1:1+n_commits]
    d1poly      = proof[1+n_commits]
    open_mesgs  = proof[2+n_commits:2+n_commits+n_commits]
    first_mesgs = proof[2+n_commits+n_commits]
    xi, queries = ldt_recover_challenges(_poly_len,h_state,commits,d1poly,Nq, RS_rho, verbose )

    if not mt.batchverify( queries , first_commit , first_mesgs ) : return False

    return ldt_verify_proof(commits,d1poly,[path[0] for path in first_mesgs],open_mesgs,xi,queries,1<<63,verbose)
#endif

int frildt_verify( const uint8_t * proof , unsigned poly_len , const uint8_t *h_state )
{
    frildt_proof_t ptr_proof;
    frildt_proof_setptr( &ptr_proof , (uint8_t *)proof );

    uint32_t queries[FRI_N_QUERY];
    uint64_t xi[FRI_CORE_N_COMMITS*FRI_GF_NUMU64];
    uint64_t d1poly[2*FRI_GF_NUMU64];

    frildt_recover_challenges( queries , d1poly , xi , h_state , poly_len , ptr_proof.commits[0] );
    //printf("query_idx: %d\n", queries[0]);

    return mt_batchverify( ptr_proof.first_commit , ptr_proof.first_mesgs , FRI_MT_MESG_LEN , FRI_MT_N_MESG , queries , FRI_N_QUERY );
}
