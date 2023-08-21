
#include "aurora.h"

#define _HASHLEN_N_U64       (PREON_HASH_LEN/8)




#if 0
def generate_proof( R1CS , h_state , Nq = 26 , RS_rho = 8 , RS_shift=1<<63 , verbose = 1 ) :
    if 1 == verbose : dump = print
    else : dump = _dummy

    ## process R1CS
    mat_A , mat_B , mat_C , vec_z , witness_idx = R1CS
    n = mat_A.n_cols
    m = mat_A.n_rows
    pad_len = _pad_len( max(n,m) )
    dump( f"m(#rows): {m} x n: {n}, witness_idx: {witness_idx}, pad_len: {pad_len}" )

    f_w ,  p_vec_z , f_Az , f_Bz , f_Cz , v_Az , v_Bz , v_Cz = process_R1CS( R1CS , verbose )

    ## row check
    dump( "rowcheck" )
    f_rowcheck = row_check(v_Az, v_Bz, v_Cz , pad_len , verbose=0 )

    ## generate random polynomials of degree 2xpad_len: r_lincheck and r_ldt
    v_r_lincheck = [ gf.from_bytes(rd.randombytes(gf.GF_BSIZE)) for _ in range(pad_len*2) ]
    for i in range(pad_len): v_r_lincheck[0] ^= v_r_lincheck[i]
    r_lincheck = gf.ifft(v_r_lincheck, 1 , 0 )
    dump( f"r_lincheck: [{len(r_lincheck)}]: ...[{pad_len-2}:{pad_len+2}] ...", r_lincheck[pad_len-2:pad_len+2] )
    r_ldt = [ gf.from_bytes(rd.randombytes(gf.GF_BSIZE)) for _ in range(pad_len*2) ]

    proof = []
    ## first commit them: HASH their RS codeword
    dump( "commit f_w, f_Az, f_Bz , f_Cz, r_lincheck , r_ldt" )
    rt0 , mesgs0 , r_leaf0 , mktree0 = commit_polys( [f_w , f_Az , f_Bz , f_Cz , r_lincheck , r_ldt ] , 2*pad_len , RS_rho , RS_shift , verbose )
    proof.append( rt0 )
    h_state = H.gen( h_state , rt0 )

    ## lin check
    chals = [ H.gen( h_state , bytes([1,i]) )[:gf.GF_BSIZE] for i in range(1,5) ]
    alpha, s1, s2, s3 = gf.from_bytes(chals[0]), gf.from_bytes(chals[1]), gf.from_bytes(chals[2]), gf.from_bytes(chals[3])
    vs    = lincheck_step1( alpha , mat_A , mat_B , mat_C , pad_len , 1 , verbose )
    g , h = lincheck_step2( *vs , p_vec_z , v_Az , v_Bz , v_Cz , s1 , s2 , s3  , r_lincheck , pad_len , verbose )
    rt1 , mesgs1 , r_leaf1 , mktree1 = commit_polys( [ h ] , 2*pad_len , RS_rho , RS_shift , verbose )
    proof.append( rt1 )
    h_state = H.gen( *chals )

    ## generate f0 for fri_ldt and perform fri_ldt
    y = [ gf.from_bytes( H.gen( h_state , bytes([2,i]) )[:gf.GF_BSIZE] ) for i in range(1,10) ]
    g_raise = gf.ipolydiv([0]+g[:pad_len-1],0)  # raise g by degree 1. It still has to be raised by pad_len.
    f0 = [ gf.mul(y[0],f_w[i])^gf.mul(y[1],f_Az[i])^gf.mul(y[2],f_Bz[i])^gf.mul(y[3],f_Cz[i])
          ^gf.mul(y[4],f_rowcheck[i])
          ^gf.mul(y[5],r_lincheck[i])^gf.mul(y[6],h[i]) ^r_ldt[i]
          ^gf.mul(y[7],g[i])
           for i in range(pad_len) ] + [ 
           gf.mul(y[5],r_lincheck[pad_len+i])^r_ldt[pad_len+i]
          ^gf.mul(y[8],rgi)
           for i,rgi in enumerate(g_raise) ]
    ## LDT f0
    dump( "ldt |f0|:", len(f0) )
    v_f0 = gf.fft( f0 , RS_rho , RS_shift )
    dump( "calculate RS code of f0: |v_f0|: " , len(v_f0) )
    dump( "commit phash" )
    st = time.time()
    ldt_commits , ldt_d1poly , ldt_mktrees , h_state = fri.ldt_commit_phase( v_f0 , len(f0) , h_state , RS_rho , RS_shift, verbose=0 )
    ed = time.time()
    dump( "time:" , format(ed-st) , "secs" )
    dump( "query phash" )
    st = time.time()
    ldt_open_mesgs , ldt_queries = fri.ldt_query_phase( len(f0) , ldt_mktrees , h_state , Nq , RS_rho , verbose=0 )
    ed = time.time()
    dump( "time:" , format(ed-st) , "secs" )
    dump( "ldt queries:" , ldt_queries )

    proof.extend( ldt_commits )
    proof.append( ldt_d1poly )
    proof.extend( ldt_open_mesgs )

    ## open queries
    proof.append( mt.batchopen(ldt_queries,mesgs0,r_leaf0,mktree0) )
    proof.append( mt.batchopen(ldt_queries,mesgs1,r_leaf1,mktree1) )

    return proof
#endif




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
