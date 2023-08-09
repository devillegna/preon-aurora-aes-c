
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




#include "aes128r1cs.h"








int test_enc0()
{
	printf("\ntest aes128 encryption\n" );


    uint8_t vec_z[R1CS_Z_LEN];
    uint8_t pt[16];  for(int i=0;i<16;i++) pt[i] = i*16+i;
    uint8_t key[16]; for(int i=0;i<16;i++) key[i] = i;

    uint8_t ct[16] = { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x4, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };

    r1cs_get_vec_z( vec_z , pt , key );

    if ( 1 != vec_z[0] ) { printf("vec_z[0] != 1\n"); return -1; }
    if ( !check_eq(ct,vec_z+1,16) )  { printf("vec_z+1  != ct\n"); return -1; }
    if ( !check_eq(pt,vec_z+17,16) ) { printf("vec_z+17 != pt\n"); return -1; }

	//printf("\n%s for %d tests.\n", (eq)?"OK":"ERROR" , TEST_RUN );

    //return (eq)?0:-1;
    return 0;
}






int main(void)
{
	printf("aes128 R1CS test.\n\n");

	int fail = 0;

    if(0 != test_enc0()) fail = 1;


	printf((fail)?"test FAIL\n":"test PASS\n");

	return 0;
}


