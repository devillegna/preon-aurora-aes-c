
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

#include "btfy.h"


int test_0(void)
{
    printf("test gfvec_alloc() gfvec_free().\n");

    gfvec_t vec;

    gfvec_alloc( &vec , 32 );
    randombytes( (uint8_t*)vec.sto , 32*8*GF_EXT_DEG );

    btfy_64( vec.vec[0] , 5 , 0 );
    btfy_64( vec.vec[1] , 5 , 0 );
    ibtfy_64( vec.vec[2] , 5 , 0 );

    gfvec_free( &vec );
    return 0;
}




int test_1(void)
{
    printf("test gfvec_t internal variables.\n");

    gfvec_t vec0;
    gfvec_alloc( &vec0 , 32 );
    randombytes( (uint8_t*)vec0.sto , 32*8*GF_EXT_DEG );

	gfvec_t vec1 = vec0;
	gfvec_dump( "gfvec1:" , vec1 , 0 );
	gfvec_dump( "gfvec1:" , vec1 , 1 );
	printf("vec1.len: %d\n", vec1.len );
	printf("vec1._stosize_u64: %p\n", vec1._stosize_u64 );

	gfvec_t vec2 = gfvec_slice( vec0 , 1 , 2 );

	gfvec_dump( "gfvec2:" , vec2 , 0 );


    gfvec_free( &vec0 );
    return 0;
}




int main(void)
{
	printf("test gf2192 and gfvec_t.\n\n");

	int fail = 0;

    if(0 != test_0()) fail = 1;
    if(0 != test_1()) fail = 1;


	printf((fail)?"test FAIL\n":"test PASS\n");

	return 0;
}


