


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




#include "frildt.h"


int test_0(void)
{
    printf("test ????.\n");

    return -1;
}



int main(void)
{
	printf("test fri ldt.\n\n");

	int fail = 0;

    if(0 != test_0()) fail = 1;


	printf((fail)?"test FAIL\n":"test PASS\n");

	return 0;
}


