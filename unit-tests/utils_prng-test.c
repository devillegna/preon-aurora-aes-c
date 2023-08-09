
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


int test_0(void)
{
    printf("test eq for 65 bytes results from c and python code.\n");

    uint8_t r65[] = { 0x24,0x3d,0x92,0xf5,0xa1,0x32,0x8a,0x4c,0xc9,0xf4,0xcb,0x6d,0xa6,0xe,0xe6,0xf7,0xb3,0x62,0x47,0x2f,0x7a,0xd4,0xfc,0x11,0x7e,0x36,0x46,0xc8,0x50,0x61,0x57,0x4c,0xc5,0xf7,0xd5,0x5e,0xaf,0x7a,0x12,0xda,0x20,0x12,0x3d,0x74,0x99,0x66,0xe4,0xfa,0x6d,0x41,0xb3,0x2a,0x41,0xa9,0x63,0x45,0xf2,0xff,0xf1,0xb8,0x1b,0x1a,0x5a,0x3f,0xf5,};

    uint8_t r65c[65];
    randombytes(r65c,65);

    int eq = check_eq(r65, r65c, 65 );
    printf("p:\n"); print_u8(r65,65); puts("");
    printf("c:\n"); print_u8(r65c,65); puts("");
    printf("eq: %d\n", eq );

    return (eq) ? 0 : 1;
}



int main(void)
{
	printf("utils_prng test.\n\n");

	int fail = 0;

    if(0 != test_0()) fail = 1;


	printf((fail)?"test FAIL\n":"test PASS\n");

	return 0;
}


