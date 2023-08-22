
#include "aurora.h"

#define _HASHLEN_N_U64       (PREON_HASH_LEN/8)



static void dump_u8(const unsigned char * s , const unsigned char *data, unsigned len )
{
    printf("%s", s);
	for(unsigned i=0;i<len;i++) {
		if( 0 == (i&15) ) printf("%3d: ",i);
		printf("%02x,", data[i] );
		if( 3 == (i&3) ) printf(".");
		if( 7 == (i&7) ) printf(" ");
		if( 15 == (i&15) ) printf("\n");
	}
}



#include "aes128r1cs.h"
#include "randombytes.h"

static
void process_R1CS_z( gfvec_t *f_w , gfvec_t *v_z_pad , const uint8_t * r1cs_z )
{
    //pad_len = _pad_len( max(n,m) )
    //inst_dim = _log2(witness_idx)
    unsigned pad_len = R1CS_PADLEN;
    unsigned inst_dim = R1CS_INSTANCE_DIM;

    uint64_t temp64[R1CS_PADLEN*GF_NUMU64];
    uint8_t * temp8 = (uint8_t*)temp64;

    //p_vec_z = vec_z + [ gf.from_bytes(rd.randombytes(gf.GF_BSIZE)) for _ in range(pad_len-len(vec_z)) ]   # ZK
    gfvec_alloc( v_z_pad , pad_len*2 );
    gfvec_from_u8gfvec( gfvec_slice(*v_z_pad,0,R1CS_NCOL), r1cs_z );
    randombytes( temp8 , (pad_len-R1CS_NCOL)*GF_BYTES );
    gfvec_from_u64vec( gfvec_slice(*v_z_pad,R1CS_NCOL,(pad_len-R1CS_NCOL)) , temp64 );

    gfvec_t f_z;   gfvec_alloc( &f_z , pad_len + R1CS_WITNESS_IDX );
    gfvec_ifft( gfvec_slice( f_z , 0 , pad_len ) , gfvec_slice(*v_z_pad,0, pad_len ) , 0 );             //f_z = gf.ifft( p_vec_z , 1 , 0 );   
    gfvec_fft( gfvec_slice(*v_z_pad,pad_len, pad_len ) , gfvec_slice( f_z , 0 , pad_len ) , pad_len );  // p_vec_z.extend( gf.fft( f_z , 1 , pad_len ) )

    //f_w = gf.polydiv( f_z , inst_dim )[witness_idx:] + [0]*witness_idx
    gfvec_polydiv( gfvec_slice(f_z,0,pad_len) , inst_dim );
    gfvec_borrow_slice( f_w , &f_z , R1CS_WITNESS_IDX , pad_len );
    uint8_t zero[R1CS_WITNESS_IDX] = {0};
    gfvec_from_u8gfvec( gfvec_slice(*f_w,pad_len-R1CS_WITNESS_IDX,R1CS_WITNESS_IDX) , zero );
}

static
void process_R1CS(gfvec_t *f_Az , gfvec_t *f_Bz , gfvec_t *f_Cz , gfvec_t *v_Az , gfvec_t *v_Bz , gfvec_t *v_Cz , const uint8_t * r1cs_z )
{
    unsigned pad_len = R1CS_PADLEN;

    gfvec_alloc( v_Az , pad_len*2 );
    gfvec_alloc( v_Bz , pad_len*2 );
    gfvec_alloc( v_Cz , pad_len*2 );

    gfvec_alloc( f_Az , pad_len );
    gfvec_alloc( f_Bz , pad_len );
    gfvec_alloc( f_Cz , pad_len );

    //Az = mat_x_vec( mat_A , vec_z )
    r1cs_matA_x_vec_z( v_Az->sto , r1cs_z  );
    gfvec_lift_from_u64gfvec( gfvec_slice(*v_Az,0,R1CS_NROW) );
    //Bz = mat_x_vec( mat_B , vec_z )
    r1cs_matB_x_vec_z( v_Bz->sto , r1cs_z  );
    gfvec_lift_from_u64gfvec( gfvec_slice(*v_Bz,0,R1CS_NROW) );
    //v_Az    = Az + [ gf.from_bytes(rd.randombytes(gf.GF_BSIZE)) for _ in range(pad_len-len(Az)) ]
    randombytes((uint8_t*)(v_Cz->sto), (R1CS_PADLEN-R1CS_NROW)*GF_BYTES );
    gfvec_from_u64vec( gfvec_slice(*v_Az,R1CS_NROW,R1CS_PADLEN-R1CS_NROW) , v_Cz->sto );
    //v_Bz    = Bz + [ gf.from_bytes(rd.randombytes(gf.GF_BSIZE)) for _ in range(pad_len-len(Bz)) ]
    randombytes((uint8_t*)(v_Cz->sto), (R1CS_PADLEN-R1CS_NROW)*GF_BYTES );
    gfvec_from_u64vec( gfvec_slice(*v_Bz,R1CS_NROW,R1CS_PADLEN-R1CS_NROW) , v_Cz->sto );

    //Cz = mat_x_vec( mat_C , vec_z )
    r1cs_matC_x_vec_z( v_Cz->sto , r1cs_z  );
    gfvec_lift_from_u64gfvec( gfvec_slice(*v_Cz,0,R1CS_NROW) );
    //v_Cz    = Cz + [ gf.mul(v_Az[i],v_Bz[i]) for i in range(m,pad_len) ]           # !!! XXX: need to discuss here
    gfvec_mul( gfvec_slice(*v_Cz,R1CS_NROW,R1CS_PADLEN-R1CS_NROW) , gfvec_slice(*v_Az,R1CS_NROW,R1CS_PADLEN-R1CS_NROW) , gfvec_slice(*v_Bz,R1CS_NROW,R1CS_PADLEN-R1CS_NROW) );

    //f_Az = gf.ifft( v_Az , 1 , 0 )
    //f_Bz = gf.ifft( v_Bz , 1 , 0 )
    //f_Cz = gf.ifft( v_Cz , 1 , 0 )
    gfvec_ifft( *f_Az , gfvec_slice(*v_Az,0,pad_len) , 0 );
    gfvec_ifft( *f_Bz , gfvec_slice(*v_Bz,0,pad_len) , 0 );
    gfvec_ifft( *f_Cz , gfvec_slice(*v_Cz,0,pad_len) , 0 );

    //v_Az.extend( gf.fft( f_Az , 1 , pad_len ) )
    //v_Bz.extend( gf.fft( f_Bz , 1 , pad_len ) )
    //v_Cz.extend( gf.fft( f_Cz , 1 , pad_len ) )
    gfvec_fft( gfvec_slice(*v_Az,pad_len,pad_len) , *f_Az , pad_len );
    gfvec_fft( gfvec_slice(*v_Bz,pad_len,pad_len) , *f_Bz , pad_len );
    gfvec_fft( gfvec_slice(*v_Cz,pad_len,pad_len) , *f_Cz , pad_len );
}



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


static
void first_commit( mt_t mt1 , gfvec_t mesgs1 , gfvec_t f_w , gfvec_t f_Az , gfvec_t f_Bz , gfvec_t f_Cz , gfvec_t r_lincheck , gfvec_t r_ldt )
{
    gfvec_t rs_code;
    gfvec_alloc(&rs_code,AURORA_MT_N_MESG*2);
    gfvec_fft(rs_code,f_w,RS_SHIFT);
    gfvec_2gfele_to_u64vec_slice( mesgs1.sto + 0*2*GF_NUMU64 , 6*2*GF_NUMU64 , rs_code );
uint64_t * ptr;
ptr = &mesgs1.sto[0];
printf("[RS] f_W: %llx %llx %llx, %llx %llx %llx\n",ptr[0],ptr[1],ptr[2], ptr[3],ptr[4],ptr[5]);
    gfvec_fft(rs_code,f_Az,RS_SHIFT);
    gfvec_2gfele_to_u64vec_slice( mesgs1.sto + 1*2*GF_NUMU64 , 6*2*GF_NUMU64 , rs_code );
ptr = &mesgs1.sto[6];
printf("[RS] f_Az: %llx %llx %llx, %llx %llx %llx\n",ptr[0],ptr[1],ptr[2], ptr[3],ptr[4],ptr[5]);
    gfvec_fft(rs_code,f_Bz,RS_SHIFT);
    gfvec_2gfele_to_u64vec_slice( mesgs1.sto + 2*2*GF_NUMU64 , 6*2*GF_NUMU64 , rs_code );
ptr = &mesgs1.sto[12];
printf("[RS] f_Bz: %llx %llx %llx, %llx %llx %llx\n",ptr[0],ptr[1],ptr[2], ptr[3],ptr[4],ptr[5]);
    gfvec_fft(rs_code,f_Cz,RS_SHIFT);
    gfvec_2gfele_to_u64vec_slice( mesgs1.sto + 3*2*GF_NUMU64 , 6*2*GF_NUMU64 , rs_code );
ptr = &mesgs1.sto[18];
printf("[RS] f_Cz: %llx %llx %llx, %llx %llx %llx\n",ptr[0],ptr[1],ptr[2], ptr[3],ptr[4],ptr[5]);
    gfvec_fft(rs_code,r_lincheck,RS_SHIFT);
    gfvec_2gfele_to_u64vec_slice( mesgs1.sto + 4*2*GF_NUMU64 , 6*2*GF_NUMU64 , rs_code );
ptr = &mesgs1.sto[24];
printf("[RS] r_lin: %llx %llx %llx, %llx %llx %llx\n",ptr[0],ptr[1],ptr[2], ptr[3],ptr[4],ptr[5]);
    gfvec_fft(rs_code,r_ldt,RS_SHIFT);
    gfvec_2gfele_to_u64vec_slice( mesgs1.sto + 5*2*GF_NUMU64 , 6*2*GF_NUMU64 , rs_code );
ptr = &mesgs1.sto[30];
printf("[RS] r_ldt: %llx %llx %llx, %llx %llx %llx\n",ptr[0],ptr[1],ptr[2], ptr[3],ptr[4],ptr[5]);
    gfvec_free(&rs_code);

    mt_commit(mt1,(uint8_t*)mesgs1.sto,AURORA_MT_MESG0_LEN,AURORA_MT_N_MESG);
}


int aurora_generate_proof( uint8_t * proof , const uint8_t * r1cs_z , const uint8_t * h_state)
{
dump_u8("h_state\n",h_state,PREON_HASH_LEN);
    gfvec_t f_w, v_z_pad;
    process_R1CS_z( &f_w , &v_z_pad , r1cs_z );
    gfvec_t f_Az, f_Bz, f_Cz, v_Az, v_Bz, v_Cz;
    process_R1CS( &f_Az , &f_Bz , &f_Cz , &v_Az , &v_Bz , &v_Cz , r1cs_z );

    unsigned pad_len = R1CS_PADLEN;
    gfvec_t v_r_lincheck; gfvec_alloc(&v_r_lincheck,2*pad_len);
    gfvec_t r_lincheck;   gfvec_alloc(&r_lincheck,  2*pad_len);
    gfvec_t r_ldt;        gfvec_alloc(&r_ldt,       2*pad_len);

    //v_r_lincheck = [ gf.from_bytes(rd.randombytes(gf.GF_BSIZE)) for _ in range(pad_len*2) ]
    randombytes( (uint8_t*)(r_lincheck.sto) , 2*pad_len*GF_BYTES );
    gfvec_from_u64vec( v_r_lincheck , r_lincheck.sto );
    //r_ldt = [ gf.from_bytes(rd.randombytes(gf.GF_BSIZE)) for _ in range(pad_len*2) ]
    randombytes( (uint8_t*)(r_lincheck.sto) , 2*pad_len*GF_BYTES );
    gfvec_from_u64vec( r_ldt , r_lincheck.sto );
    //for i in range(pad_len): v_r_lincheck[0] ^= v_r_lincheck[i]
    gfvec_lincheck_reduce( gfvec_slice(v_r_lincheck,0,pad_len) );
    //r_lincheck = gf.ifft(v_r_lincheck, 1 , 0 )
    gfvec_ifft(r_lincheck, v_r_lincheck , 0 );

    // first commit  // commit_polys( [f_w , f_Az , f_Bz , f_Cz , r_lincheck , r_ldt ]
    gfvec_t first_mesgs;  gfvec_alloc(&first_mesgs,AURORA_MT_MESG0_LEN*AURORA_MT_N_MESG/GF_BYTES);
    mt_t first_mt;   mt_init(&first_mt,AURORA_MT_N_MESG);
    first_commit(first_mt,first_mesgs,f_w,f_Az,f_Bz,f_Cz,r_lincheck,r_ldt);
    memcpy( proof , first_mt.root , PREON_HASH_LEN );  proof += PREON_HASH_LEN;
    hash_2mesg(h_state,h_state,PREON_HASH_LEN,first_mt.root,PREON_HASH_LEN);

dump_u8("mt root\n",first_mt.root,PREON_HASH_LEN);
dump_u8("h_state\n",h_state,PREON_HASH_LEN);


    // lin-check and second commit


    // generate the polynomial for ldt


    // open queries


    // clean
    gfvec_free(&first_mesgs);
    mt_free(&first_mt);

    gfvec_free(&v_r_lincheck);
    gfvec_free(&r_lincheck);
    gfvec_free(&r_ldt);
    gfvec_free(&f_w);
    gfvec_free(&v_z_pad);
    gfvec_free(&f_Az);
    gfvec_free(&f_Bz);
    gfvec_free(&f_Cz);
    gfvec_free(&v_Az);
    gfvec_free(&v_Bz);
    gfvec_free(&v_Cz);

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
