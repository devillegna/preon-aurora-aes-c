
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




#include "utils_hash.h"


int test_0()
{
    hash_ctx ctx0, ctx1, ctx2;

    uint8_t in[48]; for(int i=0;i<48;i++) in[i]=i;
    uint8_t out0[32];
    uint8_t out1[32];
    uint8_t out2[32];

    hash_init( &ctx0 );
    hash_update( &ctx0, in, 48 );
    hash_final_digest( out0 , &ctx0 );

    hash_init( &ctx1 );
    hash_update( &ctx1, in , 32 );
    hash_ctx_copy( &ctx2, &ctx1 );
    hash_update( &ctx1, in+32 , 16 );
    hash_final_digest( out1 , &ctx1 );

    hash_update( &ctx2, in+32 , 16 );
    hash_final_digest( out2 , &ctx2 );

    print_u8( out0, 32 );
    puts("");

    print_u8( out1, 32 );
    puts("");

    print_u8( out2, 32 );
    puts("");

    int eq = check_eq(out1, out2, 32 );
    eq    &= check_eq(out0, out1, 32 );

    return (eq) ? 0 : 1;
}



int main(void)
{
	printf("utils_hash test.\n\n");

	int fail = 0;

    if(0 != test_0()) fail = 1;


	printf((fail)?"test FAIL\n":"test PASS\n");

	return 0;
}


