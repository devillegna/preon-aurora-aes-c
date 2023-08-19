
#include "aurora.h"

#define _HASHLEN_N_U64       (PREON_HASH_LEN/8)



int aurora_generate_proof( uint8_t * proof , const uint8_t * r1cs_z , const uint8_t * h_state)
{

    return 0;
}




#if 0
def verify_proof( proof , R1CS , h_state , RS_rho = 8 , RS_shift=1<<63, verbose = 1 ) :
    if 1 == verbose : dump = print
    else : dump = _dummy

    ## process R1CS
    mat_A , mat_B , mat_C , vec_1v , witness_idx = R1CS
    n = mat_A.n_cols
    m = mat_A.n_rows
    pad_len = _pad_len( max(n,m) )
    dump( f"m(#rows): {m} x n: {n}, witness_idx: {witness_idx}, pad_len: {pad_len}" )

    inst_dim = _log2(witness_idx)
    r1cs_dim = _log2(pad_len)

    ## unpack proof
    rt0 = proof[0]
    rt1 = proof[1]
    _poly_len = 2*pad_len
    ldt_n_commits = fri.ldt_n_commit( _poly_len )
    ldt_commits     = proof[2:2+ldt_n_commits]
    ldt_d1poly      = proof[2+ldt_n_commits]
    ldt_open_mesgs  = proof[3+ldt_n_commits:3+ldt_n_commits+ldt_n_commits]

    open_mesgs0 = proof[3+2*ldt_n_commits]
    open_mesgs1 = proof[4+2*ldt_n_commits]

    ## recover challenges
    dump( "recover challenges" )
    h_state = H.gen( h_state , rt0 )
    chals = [ H.gen( h_state , bytes([1,i]) )[:gf.GF_BSIZE] for i in range(1,5) ]
    alpha, s1, s2, s3 = gf.from_bytes(chals[0]), gf.from_bytes(chals[1]), gf.from_bytes(chals[2]), gf.from_bytes(chals[3])
    h_state = H.gen( *chals )
    y = [ gf.from_bytes( H.gen( h_state , bytes([2,i]) )[:gf.GF_BSIZE] ) for i in range(1,10) ]
    Nq = len(open_mesgs0)
    xi, queries = fri.ldt_recover_challenges(_poly_len,h_state,ldt_commits,ldt_d1poly,Nq, RS_rho, verbose=0 )

    dump( "check if commits are opened correctly" )
    if not mt.batchverify(queries,rt0,open_mesgs0) :
        dump( "open0 fails" )
        return False
    if not mt.batchverify(queries,rt1,open_mesgs1) :
        dump( "open1 fails" )
        return False
    dump( "all passed" )

    rs_codewords = codewords_of_public_polynomials( alpha , vec_1v , mat_A , mat_B , mat_C , pad_len , RS_rho , RS_shift , verbose )

    dump( "recover first opened commit of ldt from the virtual oracle of aurora" )
    ldt_1st_mesgs = [ values_from_virtual_oracle( _idx , open_mesgs0[k][0] , open_mesgs1[k][0] , (s1,s2,s3)
                                 , y , rs_codewords , inst_dim , r1cs_dim , RS_shift ) for k,_idx in enumerate(queries) ]

    dump("verify ldt")
    ldt_r = fri.ldt_verify_proof(ldt_commits,ldt_d1poly,ldt_1st_mesgs,ldt_open_mesgs,xi,queries,RS_shift,verbose=0)
    dump( ldt_r )
    if not ldt_r : return False

    dump("all passed") 
    return True
#endif

#include "string.h"

bool aurora_verify_proof( const uint8_t * proof , const uint8_t * r1cs_z , const uint8_t * _h_state )
{
    aurora_proof_t prf;  aurora_proof_setptr(&prf,proof);

    uint8_t h_state[PREON_HASH_LEN];  memcpy(h_state,_h_state,PREON_HASH_LEN);
    // recover challenges
    //h_state = H.gen( h_state , rt0 )
    hash_2mesg( h_state , h_state , PREON_HASH_LEN , prf.commit0 , PREON_HASH_LEN );
    //chals = [ H.gen( h_state , bytes([1,i]) )[:gf.GF_BSIZE] for i in range(1,5) ]
    //alpha, s1, s2, s3 = gf.from_bytes(chals[0]), gf.from_bytes(chals[1]), gf.from_bytes(chals[2]), gf.from_bytes(chals[3])
    uint8_t bytes[2] = {1,1};

    uint64_t ch[4*GF_NUMU64+_HASHLEN_N_U64];  // alpha , s1 , s2 , s3
    for(int i=0;i<4;i++) {
        bytes[1] = 1+i;
        hash_2mesg((uint8_t*)&ch[i*GF_NUMU64],h_state,PREON_HASH_LEN,bytes,2);
    }
    //h_state = H.gen( *chals )
    hash_1mesg(h_state,(uint8_t*)ch, 4*GF_BYTES);

    //y = [ gf.from_bytes( H.gen( h_state , bytes([2,i]) )[:gf.GF_BSIZE] ) for i in range(1,10) ]
    uint64_t y[9*GF_NUMU64+_HASHLEN_N_U64];
    bytes[0]=2;
    for(int i=0;i<9;i++) {
        bytes[1] = 1+i;
        hash_2mesg((uint8_t*)&y[i*GF_NUMU64],h_state,PREON_HASH_LEN,bytes,2);
    }

    uint32_t queries[PREON_N_QUERY];
    uint64_t d1poly[FRI_GF_NUMU64*2];
    uint64_t xi[FRI_GF_NUMU64*FRI_CORE_N_XI];
    //xi, queries = fri.ldt_recover_challenges(_poly_len,h_state,ldt_commits,ldt_d1poly,Nq, RS_rho, verbose=0 )
    frildt_recover_challenges( queries , d1poly , xi , h_state , prf.fri_proof );

    if( !mt_batchverify(prf.commit0,prf.open_mesgs0,AURORA_MT_MESG0_LEN,AURORA_MT_N_MESG,queries,PREON_N_QUERY) ) return false;
    if( !mt_batchverify(prf.commit1,prf.open_mesgs1,AURORA_MT_MESG1_LEN,AURORA_MT_N_MESG,queries,PREON_N_QUERY) ) return false;


    return true;
}
