


#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>



void print_u8(const unsigned char *data, unsigned len )
{
	for(unsigned i=0;i<len;i++) {
		if( 0 == (i&15) ) printf("%3d: ",i);
		printf("%02x,", data[i] );
		if( 3 == (i&3) ) printf(".");
		if( 7 == (i&7) ) printf(" ");
		if( 15 == (i&15) ) printf("\n");
	}
}


uint8_t check_eq( const uint8_t *vec0, const uint8_t *vec1, unsigned len)
{
	uint8_t diff = 0;
	for(unsigned i=0;i<len;i++){
		diff |= vec0[i]^vec1[i];
	}
	return diff==0;
}



#include "randombytes.h"
#include "gfvec.h"
#include "frildt.h"

#define POLYLEN    FRI_POLYLEN
#define LOGPOLYLEN FRI_LOGPOLYLEN

int test_0(void)
{
    printf("test gen proof([%d])/verify.\n", POLYLEN );
	printf("polylen: %d , log_polylen: %d\n", POLYLEN , LOGPOLYLEN );
	printf("proof size: %d\n", FRI_PROOF_LEN(LOGPOLYLEN+FRI_RS_LOGRHO) );

    gfvec_t vec;
    gfvec_alloc( &vec , POLYLEN );
    randombytes( (uint8_t*)vec.vec[0] , POLYLEN*FRI_GF_BYTELEN );

    uint8_t h_state[FRI_HASH_LEN];
    randombytes( h_state , FRI_HASH_LEN );

    uint8_t proof[FRI_PROOF_LEN(LOGPOLYLEN+FRI_RS_LOGRHO)];
    frildt_gen_proof( proof , &vec , h_state );

    int succ = frildt_verify( proof , POLYLEN , h_state );

	gfvec_free( &vec );
    return succ;
}



int main(void)
{
	printf("test fri ldt.\n\n");

	int fail = 0;

    if( ! test_0()) fail = 1;


	printf((fail)?"test FAIL\n":"test PASS\n");

	return 0;
}


