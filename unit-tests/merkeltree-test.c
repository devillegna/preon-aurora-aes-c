
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




#include "merkeltreecommit.h"


int test_0(void)
{
    uint8_t mesgs[4*8]; for(int i=0;i<sizeof(mesgs);i++) mesgs[i]=i;
    uint8_t auth_path[4+MT_AUTH_OVERHEAD_LEN(3)];
    uint8_t root[HASH_DIGEST_LEN];

    mt_t tree;

    if( mt_init( &tree , 8 ) ) {
        printf("mt_init() fails.\n");
        return -1;
    }

    if( mt_commit( &tree , mesgs , 4 , 8 ) ) {
        printf("mt_commit() fails.\n");
        return -1;
    }
    memmove( root , tree.root , HASH_DIGEST_LEN );

    unsigned idx = 5;
    if( mt_open( auth_path , tree , mesgs+4*idx , 4 , idx ) ) {
        printf("mt_open() fails.\n");
        return -1;
    }
    mt_free( &tree );


    int v0 = mt_verify( root , auth_path , 4 , 8 , idx );
    if(!v0) {
        printf("mt_verify(correct path) fails.\n");
        return -1;
    }

    int v1 = mt_verify( root , auth_path , 4 , 8 , idx^1 );
    if(v1) {
        printf("mt_verify(wrong path) fails.\n");
        return -1;
    }

    return 0;
}



int main(void)
{
	printf("merkeltreecommit test.\n\n");

	int fail = 0;

    if(0 != test_0()) fail = 1;


	printf((fail)?"test FAIL\n":"test PASS\n");

	return 0;
}


