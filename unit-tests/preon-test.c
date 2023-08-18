


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



#include "preon_settings.h"
#include "preon.h"


int test_0(void)
{
    uint8_t pk[PREON_PKLEN];
    uint8_t sk[PREON_SKLEN];
    uint8_t sig[PREON_SIGLEN];

    uint8_t mesg[4] = { '1','2','3','4' };


    printf("test genkey/sign/verify.\n");
    printf("pk len:%d, sk len:%d, sig len:%d, mesg len:%d\n",sizeof(pk),sizeof(sk),sizeof(sig),sizeof(mesg));


    preon_keygen( pk , sk );

    preon_sign( sig , sk , mesg , sizeof(mesg) );

    return preon_verify( sig , pk , mesg , sizeof(mesg) );
}



int main(void)
{
	printf("test preon.\n\n");

	int succ = 1;

    if( ! test_0()) succ = 0;


	printf((succ)?"all PASS\n":"some FAIL\n");

	return 0;
}


