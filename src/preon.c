
#include "preon.h"

#include "randombytes.h"

#include <openssl/evp.h>
#include <openssl/aes.h>

#include "string.h"

int preon_keygen( uint8_t * pk , uint8_t * sk )
{
    uint8_t aes_key[PREON_AESKEYLEN];
    uint8_t aes_pt[16];
    uint8_t aes_ct[16];

    randombytes( aes_key , sizeof(aes_key) );
    randombytes( aes_pt , sizeof(aes_pt) );

#if defined(_PREON_128_)
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, aes_key, NULL);
    int c_len = 16;
    EVP_EncryptUpdate(ctx, aes_ct, &c_len, aes_pt, 16);
    EVP_CIPHER_CTX_free(ctx);
#else
error here
#endif

    memcpy( pk , aes_pt , sizeof(aes_pt) );  pk += sizeof(aes_pt);
    memcpy( pk , aes_ct , sizeof(aes_ct) );

    memcpy( sk , aes_pt , sizeof(aes_pt) );  sk += sizeof(aes_pt);
    memcpy( sk , aes_key , sizeof(aes_key) );

    return 0;
}


int preon_sign( uint8_t * sig , const uint8_t * sk , const uint8_t * mesg , unsigned len_mesg )
{

    return 0;
}

int preon_verify( const uint8_t * sig , const uint8_t * pk , const uint8_t * mesg , unsigned len_mesg )
{

    return 0;
}




