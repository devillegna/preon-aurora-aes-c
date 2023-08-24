
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
    gfvec_set_zero( gfvec_slice(*f_w,pad_len-R1CS_WITNESS_IDX,R1CS_WITNESS_IDX) );
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



static
void first_commit( mt_t mt1 , gfvec_t mesgs1 , gfvec_t f_w , gfvec_t f_Az , gfvec_t f_Bz , gfvec_t f_Cz , gfvec_t r_lincheck , gfvec_t r_ldt )
{
    gfvec_t rs_code;
    gfvec_alloc(&rs_code,AURORA_MT_N_MESG*2);
    gfvec_fft(rs_code,f_w,RS_SHIFT);
    gfvec_2gfele_to_u64vec_slice( mesgs1.sto + 0*2*GF_NUMU64 , 6*2*GF_NUMU64 , rs_code );
    gfvec_fft(rs_code,f_Az,RS_SHIFT);
    gfvec_2gfele_to_u64vec_slice( mesgs1.sto + 1*2*GF_NUMU64 , 6*2*GF_NUMU64 , rs_code );
    gfvec_fft(rs_code,f_Bz,RS_SHIFT);
    gfvec_2gfele_to_u64vec_slice( mesgs1.sto + 2*2*GF_NUMU64 , 6*2*GF_NUMU64 , rs_code );
    gfvec_fft(rs_code,f_Cz,RS_SHIFT);
    gfvec_2gfele_to_u64vec_slice( mesgs1.sto + 3*2*GF_NUMU64 , 6*2*GF_NUMU64 , rs_code );
    gfvec_fft(rs_code,r_lincheck,RS_SHIFT);
    gfvec_2gfele_to_u64vec_slice( mesgs1.sto + 4*2*GF_NUMU64 , 6*2*GF_NUMU64 , rs_code );
    gfvec_fft(rs_code,r_ldt,RS_SHIFT);
    gfvec_2gfele_to_u64vec_slice( mesgs1.sto + 5*2*GF_NUMU64 , 6*2*GF_NUMU64 , rs_code );
    gfvec_free(&rs_code);

    mt_commit(mt1,(uint8_t*)mesgs1.sto,AURORA_MT_MESG0_LEN,AURORA_MT_N_MESG);
}




static
void lin_check(gfvec_t *g, gfvec_t *h, const uint64_t *chals , gfvec_t v_Az, gfvec_t v_Bz, gfvec_t v_Cz, gfvec_t v_z_pad , gfvec_t r_lincheck )
{
    const uint64_t *alpha = chals;
    const uint64_t *s1 = chals + 1*GF_NUMU64;
    const uint64_t *s2 = chals + 2*GF_NUMU64;
    const uint64_t *s3 = chals + 3*GF_NUMU64;

    gfvec_t temp2;  gfvec_alloc(&temp2, 2*R1CS_POLYLEN);
    gfvec_t temp = gfvec_slice(temp2,0,R1CS_POLYLEN);

    // generate v_alpha
    gfvec_t v_alpha;  gfvec_alloc(&v_alpha, R1CS_POLYLEN*2);
    gfvec_set_zero( gfvec_slice(v_alpha,0,1) );   v_alpha.vec[0][0]=1;
    gfvec_from_u64vec(gfvec_slice(v_alpha,1,1),alpha);
    for(unsigned i=2;i<R1CS_NROW;i++) gfvec_mul_scalar2(gfvec_slice(v_alpha,i,1),gfvec_slice(v_alpha,i-1,1),alpha);
    gfvec_set_zero( gfvec_slice(v_alpha,R1CS_NROW,R1CS_PADLEN-R1CS_NROW) );
    // extend length from R1CS_POLYLEN to 2*R1CS_POLYLEN
    gfvec_ifft(temp,gfvec_slice(v_alpha,0,R1CS_POLYLEN),0);
    gfvec_fft(gfvec_slice(v_alpha,R1CS_POLYLEN,R1CS_POLYLEN),temp,R1CS_POLYLEN);
    // generate v_p2A
    gfvec_t v_p2A;  gfvec_alloc(&v_p2A, R1CS_POLYLEN*2);
    for(unsigned i=0;i<GF_EXT_DEG;i++) { r1cs_matA_colvec_dot(v_p2A.vec[i],v_alpha.vec[i]); }
    gfvec_set_zero( gfvec_slice(v_p2A,R1CS_NCOL,R1CS_PADLEN-R1CS_NCOL) );
    gfvec_ifft(temp,gfvec_slice(v_p2A,0,R1CS_POLYLEN),0);
    gfvec_fft(gfvec_slice(v_p2A,R1CS_POLYLEN,R1CS_POLYLEN),temp,R1CS_POLYLEN);
    // generate v_p2B
    gfvec_t v_p2B;  gfvec_alloc(&v_p2B, R1CS_POLYLEN*2);
    for(unsigned i=0;i<GF_EXT_DEG;i++) { r1cs_matB_colvec_dot(v_p2B.vec[i],v_alpha.vec[i]); }
    gfvec_set_zero( gfvec_slice(v_p2B,R1CS_NCOL,R1CS_PADLEN-R1CS_NCOL) );
    gfvec_ifft(temp,gfvec_slice(v_p2B,0,R1CS_POLYLEN),0);
    gfvec_fft(gfvec_slice(v_p2B,R1CS_POLYLEN,R1CS_POLYLEN),temp,R1CS_POLYLEN);
    // generate v_p2C
    gfvec_t v_p2C;  gfvec_alloc(&v_p2C, R1CS_POLYLEN*2);
    for(unsigned i=0;i<GF_EXT_DEG;i++) { r1cs_matC_colvec_dot(v_p2C.vec[i],v_alpha.vec[i]); }
    gfvec_set_zero( gfvec_slice(v_p2C,R1CS_NCOL,R1CS_PADLEN-R1CS_NCOL) );
    gfvec_ifft(temp,gfvec_slice(v_p2C,0,R1CS_POLYLEN),0);
    gfvec_fft(gfvec_slice(v_p2C,R1CS_POLYLEN,R1CS_POLYLEN),temp,R1CS_POLYLEN);
    
    //dump( f"lin-check step 2. poly muls and /Z_{_log2(pad_len)}" )
    //v_sA = [ gf.mul(v_Az[i],v_alpha[i]) ^ gf.mul(p_vec_z[i],v_p2A[i]) for i in range(2*pad_len) ]
    //v_sB = [ gf.mul(v_Bz[i],v_alpha[i]) ^ gf.mul(p_vec_z[i],v_p2B[i]) for i in range(2*pad_len) ]
    //v_sC = [ gf.mul(v_Cz[i],v_alpha[i]) ^ gf.mul(p_vec_z[i],v_p2C[i]) for i in range(2*pad_len) ]
    //f_sA = gf.ifft( v_sA , 1 , 0 )
    //f_sB = gf.ifft( v_sB , 1 , 0 )
    //f_sC = gf.ifft( v_sC , 1 , 0 )
    //g = [ gf.mul(s1,f_sA[i])^gf.mul(s2,f_sB[i])^gf.mul(s3,f_sC[i])^r_lincheck[i] for i in range(pad_len) ]
    //h = [ gf.mul(s1,f_sA[i])^gf.mul(s2,f_sB[i])^gf.mul(s3,f_sC[i])^r_lincheck[i] for i in range(pad_len,2*pad_len) ]
    gfvec_mul( temp2 , v_Az , v_alpha );
    gfvec_mul( v_p2A , v_p2A , v_z_pad );
    gfvec_add( v_p2A , v_p2A , temp2 );
    gfvec_mul_scalar( v_p2A , s1 );

    gfvec_mul( temp2 , v_Bz , v_alpha );
    gfvec_mul( v_p2B , v_p2B , v_z_pad );
    gfvec_add( v_p2B , v_p2B , temp2 );
    gfvec_mul_scalar( v_p2B , s2 );

    gfvec_mul( temp2 , v_Cz , v_alpha );
    gfvec_mul( v_p2C , v_p2C , v_z_pad );
    gfvec_add( v_p2C , v_p2C , temp2 );
    gfvec_mul_scalar( v_p2C , s3 );

    gfvec_add( v_p2A , v_p2A , v_p2B );
    gfvec_add( v_p2A , v_p2A , v_p2C );
    gfvec_ifft( temp2 , v_p2A , 0 );

    gfvec_alloc(g, R1CS_POLYLEN);
    gfvec_alloc(h, R1CS_POLYLEN);
    gfvec_add( *g, gfvec_slice(temp2,0,R1CS_POLYLEN) , gfvec_slice(r_lincheck,0,R1CS_POLYLEN) );
    gfvec_add( *h, gfvec_slice(temp2,R1CS_POLYLEN,R1CS_POLYLEN) , gfvec_slice(r_lincheck,R1CS_POLYLEN,R1CS_POLYLEN) );

    // check if g[-1] == 0
//printf("g[4094,4095]: %llx %llx %llx, %llx %llx %llx\n",g->vec[0][4094],g->vec[1][4094],g->vec[2][4094],g->vec[0][4095],g->vec[1][4095],g->vec[2][4095]);

    gfvec_free(&v_p2A);
    gfvec_free(&v_p2B);
    gfvec_free(&v_p2C);
    gfvec_free(&v_alpha);
    gfvec_free(&temp2);
}

#include "string.h"

int aurora_generate_proof( uint8_t * proof , const uint8_t * r1cs_z , const uint8_t * h_state)
{
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

    // challenges
    uint8_t bytes[2] = {1,0};
    uint64_t chals[GF_NUMU64*4+PREON_HASH_LEN];  // for lin-check
    for(int i=0;i<4;i++) {
        bytes[1] = i+1;
        hash_2mesg((uint8_t*)&chals[GF_NUMU64*i], h_state,PREON_HASH_LEN, bytes, 2 );
    }
    hash_1mesg(h_state, (uint8_t*)chals , GF_BYTES*4 );

    // lin-check and second commit
    gfvec_t h, g;
    lin_check( &g , &h , chals , v_Az , v_Bz , v_Cz , v_z_pad , r_lincheck );

    gfvec_t tmp_rscode;  gfvec_alloc(&tmp_rscode,AURORA_POLYLEN*RS_RHO);
    gfvec_fft(tmp_rscode,h,RS_SHIFT);
    gfvec_t second_mesgs;  gfvec_alloc(&second_mesgs,AURORA_MT_MESG1_LEN*AURORA_MT_N_MESG/GF_BYTES);
    gfvec_to_u64vec( second_mesgs.sto , tmp_rscode );
    mt_t second_mt;   mt_init(&second_mt,AURORA_MT_N_MESG);
    mt_commit(second_mt,(uint8_t*)second_mesgs.sto,AURORA_MT_MESG1_LEN,AURORA_MT_N_MESG);
    memcpy( proof , second_mt.root , PREON_HASH_LEN );  proof += PREON_HASH_LEN;

    // generate the polynomial for ldt

    // row-check
    //v_AzxBz = v_Cz[:pad_len] + [ gf.mul(v_Az[i],v_Bz[i]) for i in range(pad_len,2*pad_len) ]
    //f_Azxf_Bz = gf.ifft( v_AzxBz , 1 , 0 )
    //f_rowcheck = f_Azxf_Bz[pad_len:]
    gfvec_mul( gfvec_slice(v_Cz,R1CS_POLYLEN,R1CS_POLYLEN),gfvec_slice(v_Az,R1CS_POLYLEN,R1CS_POLYLEN),gfvec_slice(v_Bz,R1CS_POLYLEN,R1CS_POLYLEN));
    gfvec_ifft( v_Az , v_Cz , 0 );
    gfvec_t f_rowcheck = gfvec_slice(v_Az,R1CS_POLYLEN,R1CS_POLYLEN);

    // raise degree of g by 1
    gfvec_t g_raise;   gfvec_alloc(&g_raise,R1CS_POLYLEN);
    gfvec_set_zero( gfvec_slice(g_raise,0,1) );
    gfvec_copy( gfvec_slice(g_raise,1,R1CS_POLYLEN-1) , gfvec_slice(g,0,R1CS_POLYLEN-1) );
    gfvec_ipolydiv(g_raise,0);

    uint64_t y[GF_NUMU64*9+PREON_HASH_LEN];  // for fri-ldt
    bytes[0] = 2;
    for(int i=0;i<9;i++) {
        bytes[1] = i+1;
        hash_2mesg((uint8_t*)&y[GF_NUMU64*i], h_state,PREON_HASH_LEN, bytes, 2 );
    }
    //f0 = [ gf.mul(y[0],f_w[i])^gf.mul(y[1],f_Az[i])^gf.mul(y[2],f_Bz[i])^gf.mul(y[3],f_Cz[i])
    //      ^gf.mul(y[4],f_rowcheck[i])
    //      ^gf.mul(y[5],r_lincheck[i])^gf.mul(y[6],h[i]) ^r_ldt[i]
    //      ^gf.mul(y[7],g[i])
    //       for i in range(pad_len) ] + [ 
    //       gf.mul(y[5],r_lincheck[pad_len+i])^r_ldt[pad_len+i]
    //      ^gf.mul(y[8],rgi)
    //       for i,rgi in enumerate(g_raise) ]
    gfvec_mul_scalar(f_w,&y[0*GF_NUMU64]);
    gfvec_mul_scalar(f_Az,&y[1*GF_NUMU64]);
    gfvec_mul_scalar(f_Bz,&y[2*GF_NUMU64]);
    gfvec_mul_scalar(f_Cz,&y[3*GF_NUMU64]);
    gfvec_mul_scalar(f_rowcheck,&y[4*GF_NUMU64]);
    gfvec_mul_scalar(r_lincheck,&y[5*GF_NUMU64]);
    gfvec_mul_scalar(h ,&y[6*GF_NUMU64]);
    gfvec_mul_scalar(g ,&y[7*GF_NUMU64]);
    gfvec_mul_scalar(g_raise ,&y[8*GF_NUMU64]);
    gfvec_add(h, h, f_w);
    gfvec_add(h, h, f_Az);
    gfvec_add(h, h, f_Bz);
    gfvec_add(h, h, f_Cz);
    gfvec_add(h, h, f_rowcheck);
    gfvec_add(h, h, g);
    gfvec_add(r_ldt, r_ldt, r_lincheck);
    gfvec_add(gfvec_slice(r_ldt,0,R1CS_POLYLEN),gfvec_slice(r_ldt,0,R1CS_POLYLEN),h);
    gfvec_add(gfvec_slice(r_ldt,R1CS_POLYLEN,R1CS_POLYLEN),gfvec_slice(r_ldt,R1CS_POLYLEN,R1CS_POLYLEN),g_raise);

    gfvec_fft(tmp_rscode,r_ldt,RS_SHIFT);

    uint32_t queries[FRI_N_QUERY];
    frildt_gen_proof_core(proof, queries, tmp_rscode, h_state);
    proof += FRI_CORE_LEN;
//printf(":queires: %d, %d, %d, %d,...\n", queries[0], queries[1], queries[2], queries[3]);
    // open queries
    mt_batchopen( proof , first_mt , (uint8_t*)first_mesgs.sto , AURORA_MT_MESG0_LEN , queries , FRI_N_QUERY );
    proof += FRI_N_QUERY*MT_AUTHPATH_LEN( AURORA_MT_MESG0_LEN,AURORA_MT_LOGMESG);
    mt_batchopen( proof , second_mt , (uint8_t*)second_mesgs.sto , AURORA_MT_MESG1_LEN , queries , FRI_N_QUERY );

    // clean
    gfvec_free(&g_raise);

    gfvec_free(&tmp_rscode);
    gfvec_free(&second_mesgs);
    mt_free(&second_mt);

    gfvec_free(&g);
    gfvec_free(&h);

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



//////////////////////////// code for verification  /////////////////////////////////////



static
void recover_v0_mesgs( uint64_t *mesg , const uint8_t * open_mesg0 , const uint8_t * open_mesg1 , const uint8_t * r1cs_1v, const uint64_t * alpha_n_s , const uint64_t * y, const uint32_t * queries );


#include "string.h"

bool aurora_verify_proof( const uint8_t * proof , const uint8_t * r1cs_1v , const uint8_t * _h_state )
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
//printf(":queires: %d, %d, %d, %d,...\n", queries[0], queries[1], queries[2], queries[3]);

    if( !mt_batchverify(prf.commit0,prf.open_mesgs0,AURORA_MT_MESG0_LEN,AURORA_MT_N_MESG,queries,PREON_N_QUERY) ) return false;
    if( !mt_batchverify(prf.commit1,prf.open_mesgs1,AURORA_MT_MESG1_LEN,AURORA_MT_N_MESG,queries,PREON_N_QUERY) ) return false;

    const uint8_t * fri_open_mesgs = frildt_proof_get_open_mesgs(prf.fri_proof);

    if( !frildt_verify_commit_open(prf.fri_proof,fri_open_mesgs,queries)) return false;

    uint64_t v0_opened[2*GF_NUMU64*FRI_N_QUERY];
    recover_v0_mesgs( v0_opened , prf.open_mesgs0 , prf.open_mesgs1 , r1cs_1v, ch , y, queries );

    //return true;
    return frildt_verify_linear_relation( (uint8_t*)v0_opened , fri_open_mesgs , (uint8_t*)d1poly , xi , queries);
}












static
void recover_public_polynomials( gfvec_t f_1v , gfvec_t f_alpha , gfvec_t f_p2A , gfvec_t f_p2B , gfvec_t f_p2C , const uint64_t * alpha , const uint8_t * r1cs_1v )
{
    gfvec_t temp;  gfvec_alloc(&temp, R1CS_POLYLEN);
    // generate f_1v
    gfvec_from_u8gfvec( gfvec_slice(temp,0,R1CS_WITNESS_IDX) , r1cs_1v );
    gfvec_ifft(f_1v,gfvec_slice(temp,0,R1CS_WITNESS_IDX), 0);

    // generate v_alpha
    gfvec_t v_alpha; gfvec_alloc(&v_alpha, R1CS_POLYLEN);
    gfvec_set_zero( gfvec_slice(v_alpha,0,1) );   v_alpha.vec[0][0]=1;
    gfvec_from_u64vec(gfvec_slice(v_alpha,1,1),alpha);
    for(unsigned i=2;i<R1CS_NROW;i++) gfvec_mul_scalar2(gfvec_slice(v_alpha,i,1),gfvec_slice(v_alpha,i-1,1),alpha);
    gfvec_set_zero( gfvec_slice(v_alpha,R1CS_NROW,R1CS_PADLEN-R1CS_NROW) );
    gfvec_ifft(f_alpha,gfvec_slice(v_alpha,0,R1CS_POLYLEN),0);
    // generate v_p2A
    gfvec_t v_p2A = temp;
    for(unsigned i=0;i<GF_EXT_DEG;i++) { r1cs_matA_colvec_dot(v_p2A.vec[i],v_alpha.vec[i]); }
    gfvec_set_zero( gfvec_slice(v_p2A,R1CS_NCOL,R1CS_PADLEN-R1CS_NCOL) );
    gfvec_ifft(f_p2A,gfvec_slice(v_p2A,0,R1CS_POLYLEN),0);
    // generate v_p2B
    gfvec_t v_p2B = temp;
    for(unsigned i=0;i<GF_EXT_DEG;i++) { r1cs_matB_colvec_dot(v_p2B.vec[i],v_alpha.vec[i]); }
    gfvec_set_zero( gfvec_slice(v_p2B,R1CS_NCOL,R1CS_PADLEN-R1CS_NCOL) );
    gfvec_ifft(f_p2B,gfvec_slice(v_p2B,0,R1CS_POLYLEN),0);
    // generate v_p2C
    gfvec_t v_p2C = temp;
    for(unsigned i=0;i<GF_EXT_DEG;i++) { r1cs_matC_colvec_dot(v_p2C.vec[i],v_alpha.vec[i]); }
    gfvec_set_zero( gfvec_slice(v_p2C,R1CS_NCOL,R1CS_PADLEN-R1CS_NCOL) );
    gfvec_ifft(f_p2C,gfvec_slice(v_p2C,0,R1CS_POLYLEN),0);

    gfvec_free(&v_alpha);
    gfvec_free(&temp);
}


#include "gf264.h"
#include "cantor_to_gf264.h"

static
void recover_v0_mesgs( uint64_t *mesg , const uint8_t * open_mesg0 , const uint8_t * open_mesg1 , const uint8_t * r1cs_1v, const uint64_t * alpha_n_s , const uint64_t * y, const uint32_t * queries )
{

    gfvec_t f_1v;    gfvec_alloc(&f_1v, R1CS_WITNESS_IDX); 
    gfvec_t f_alpha; gfvec_alloc(&f_alpha,R1CS_POLYLEN);
    gfvec_t f_p2A;   gfvec_alloc(&f_p2A,R1CS_POLYLEN);
    gfvec_t f_p2B;   gfvec_alloc(&f_p2B,R1CS_POLYLEN);
    gfvec_t f_p2C;   gfvec_alloc(&f_p2C,R1CS_POLYLEN);

    recover_public_polynomials(f_1v,f_alpha,f_p2A,f_p2B,f_p2C,alpha_n_s,r1cs_1v);

    //rs_f_1v , rs_f_alpha , rs_f_p2A, rs_f_p2B, rs_f_p2C = rs_codewords
    gfvec_t rs_f_1v;    gfvec_alloc(&rs_f_1v, RS_RHO*AURORA_POLYLEN);    gfvec_fft(rs_f_1v,f_1v,RS_SHIFT);
    gfvec_t rs_f_alpha; gfvec_alloc(&rs_f_alpha, RS_RHO*AURORA_POLYLEN); gfvec_fft(rs_f_alpha,f_alpha,RS_SHIFT);
    gfvec_t rs_f_p2A;   gfvec_alloc(&rs_f_p2A, RS_RHO*AURORA_POLYLEN);   gfvec_fft(rs_f_p2A,f_p2A,RS_SHIFT);
    gfvec_t rs_f_p2B;   gfvec_alloc(&rs_f_p2B, RS_RHO*AURORA_POLYLEN);   gfvec_fft(rs_f_p2B,f_p2B,RS_SHIFT);
    gfvec_t rs_f_p2C;   gfvec_alloc(&rs_f_p2C, RS_RHO*AURORA_POLYLEN);   gfvec_fft(rs_f_p2C,f_p2C,RS_SHIFT);

    gfvec_free(&f_1v);
    gfvec_free(&f_alpha);
    gfvec_free(&f_p2A);
    gfvec_free(&f_p2B);
    gfvec_free(&f_p2C);

    //s1 , s2, s3 = lincheck_s
    const uint64_t * s1 = alpha_n_s[1*GF_NUMU64];
    const uint64_t * s2 = alpha_n_s[2*GF_NUMU64];
    const uint64_t * s3 = alpha_n_s[3*GF_NUMU64];

    //vv0 = [ gf.from_bytes_x2(aurora_open0[i*gf.GF_BSIZE*2:i*gf.GF_BSIZE*2+gf.GF_BSIZE*2]) for i in range(6) ]
    const uint8_t * vv0[PREON_N_QUERY];
    for(int i=0;i<PREON_N_QUERY;i++) { vv0[i] = open_mesg0+i*MT_AUTHPATH_LEN( AURORA_MT_MESG0_LEN,AURORA_MT_LOGMESG);  }
    //v_w0 , v_Az0 , v_Bz0 , v_Cz0 , v_lincheck0 , v_ldt0 = vv0[0],vv0[1],vv0[2],vv0[3],vv0[4],vv0[5]

    //v_h0   = gf.from_bytes_x2(aurora_open1)
    const uint8_t * v_h0[PREON_N_QUERY];
    for(int i=0;i<PREON_N_QUERY;i++) { v_h0[i] = open_mesg1+i*MT_AUTHPATH_LEN( AURORA_MT_MESG1_LEN,AURORA_MT_LOGMESG);  }

    gfvec_t yy; gfvec_alloc(&yy,9);  gfvec_from_u64vec(yy,y);
    gfvec_t cc; gfvec_alloc(&cc,16);
    gfvec_t v_w = gfvec_slice(cc,0,1);
    gfvec_t v_Az = gfvec_slice(cc,1,1);
    gfvec_t v_Bz = gfvec_slice(cc,2,1);
    gfvec_t v_Cz = gfvec_slice(cc,3,1);
    gfvec_t v_rowc = gfvec_slice(cc,4,1);
    gfvec_t v_linc = gfvec_slice(cc,5,1);
    gfvec_t v_h = gfvec_slice(cc,6,1);
    gfvec_t v_g = gfvec_slice(cc,7,1);
    gfvec_t v_gr1 = gfvec_slice(cc,8,1);
    gfvec_t v_ldt = gfvec_slice(cc,9,1);
    gfvec_t tmp_v6 = gfvec_slice(cc,10,6);

    uint64_t tmp_gfx12[GF_NUMU64*12];
    uint64_t tmp_gfx2[GF_NUMU64*2];

    for(int i=0;i<PREON_N_QUERY;i++) {
        unsigned idx = queries[i]*2;
        memcpy(tmp_gfx12,vv0[i] ,GF_BYTES*12);
        memcpy(tmp_gfx2 ,v_h0[i],GF_BYTES*12);
        for(int j=0;j<4;j++) gfvec_from_u64vec(gfvec_slice(cc,j,1), &tmp_gfx12[j*2*GF_NUMU64]);  // v_w, v_Az, v_Bz, v_Cz
        gfvec_from_u64vec( v_linc , &tmp_gfx12[4*2*GF_NUMU64] );
        gfvec_from_u64vec( v_ldt  , &tmp_gfx12[5*2*GF_NUMU64] );

        gfvec_mul( v_rowc , v_Az , v_Bz );
        gfvec_add( v_rowc , v_rowc , v_Cz );
        gfvec_mul_scalar3( v_rowc , gf264_inv( cantor_to_gf264(RS_SHIFT+idx) ) );

        gfvec_from_u64vec( v_h , &tmp_gfx2[0*GF_NUMU64]);

    }
    gfvec_free(&yy);
    gfvec_free(&cc);

    //# generate output
    //values = []
    //for i in range(2):
    //    idx = _idx*2 + i
    //    cc0  = gf.mul(y[0],v_w0[i])^gf.mul(y[1],v_Az0[i])^gf.mul(y[2],v_Bz0[i])^gf.mul(y[3],v_Cz0[i])
    //    v_f_rowcheck0 = gf.mul( (gf.mul( v_Az0[i] , v_Bz0[i] )^v_Cz0[i]) , cgf.gf264_inv( cgf.index_to_gf264((offset+idx)>>r1cs_dim) ) )
    //    cc0 ^= gf.mul(y[4],v_f_rowcheck0)
    //    cc0 ^= gf.mul(y[5],v_lincheck0[i])^gf.mul(y[6],v_h0[i])^v_ldt0[i]
    //
    //    v_fz0 = rs_f_1v[idx]^gf.mul_gf264( v_w0[i] , cgf.index_to_gf264( (offset+idx)>>inst_dim ) )
    //
    //    v_g0 =  gf.mul( s1 , gf.mul(v_Az0[i],rs_f_alpha[idx])^gf.mul(rs_f_p2A[idx],v_fz0) ) \
    //           ^gf.mul( s2 , gf.mul(v_Bz0[i],rs_f_alpha[idx])^gf.mul(rs_f_p2B[idx],v_fz0) ) \
    //           ^gf.mul( s3 , gf.mul(v_Cz0[i],rs_f_alpha[idx])^gf.mul(rs_f_p2C[idx],v_fz0) ) \
    //           ^ v_lincheck0[i] ^ gf.mul_gf264( v_h0[i] , cgf.index_to_gf264((offset+idx)>>r1cs_dim) )
    //    cc0 ^= gf.mul(y[7],v_g0) 
    //    cc0 ^= gf.mul_gf264( gf.mul(y[8],v_g0), cgf.gf264_mul( cgf.index_to_gf264(offset+idx) , cgf.index_to_gf264((offset+idx)>>r1cs_dim) ) )
    //    values.append( cc0 )
    //return gf.to_bytes(values[0])+gf.to_bytes(values[1])

    gfvec_free(&rs_f_1v);
    gfvec_free(&rs_f_alpha);
    gfvec_free(&rs_f_p2A);
    gfvec_free(&rs_f_p2B);
    gfvec_free(&rs_f_p2C);


}






