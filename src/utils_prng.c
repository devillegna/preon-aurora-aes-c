
#include "randombytes.h"

#include "stdint.h"

#if defined(_DEBUG_PRNG_)

#include <openssl/evp.h>

static void _hash( uint8_t * digest , const uint8_t * mesg )
{
    EVP_MD_CTX *h = EVP_MD_CTX_create();
    EVP_DigestInit_ex(h, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(h, mesg, 64);
    EVP_DigestFinal(h, digest, NULL);
    EVP_MD_CTX_destroy(h);
}


#include "string.h"

static int _prng_init = 0;
static int _prng_used;
static uint8_t _prng_buff[64];


static void _prng_set_seed( const uint8_t * seed )
{
    _prng_used = 32;
    memcpy(_prng_buff,seed,64);
}

static void _prng_gen( uint8_t * out , unsigned len )
{
    if(32>_prng_used) {
        unsigned ready = 32-_prng_used;
        if(ready > len) ready = len;
        memcpy(out,_prng_buff+_prng_used,ready);
        out += ready;
        _prng_used += ready;
        len -= ready;
    }
    while( 32 <= len ) {
        _hash(_prng_buff,_prng_buff);
        memcpy(out,_prng_buff,32);
        out += 32;
        len -= 32;
    }
    if (len) {
        _hash(_prng_buff,_prng_buff);
        memcpy(out,_prng_buff,len);
        _prng_used = len;
    }
}

void randombytes( unsigned char * v , unsigned len )
{
    if(0==_prng_init) {
        uint8_t seed[64] = {0};
        _prng_set_seed(seed);
        _prng_init = 1;
    }
    _prng_gen(v,len);
}


#endif
