
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


#if 16==PREON_AESKEYLEN
#include "aes128r1cs.h"
#else
XXX: no support now.
#endif

#include "utils_hash.h"
#if PREON_HASH_LEN != HASH_DIGEST_LEN
error->HASH_LEN
#endif

#include "aurora.h"

int preon_sign( uint8_t * sig , const uint8_t * sk , const uint8_t * mesg , unsigned len_mesg )
{
    uint8_t r1cs_z[R1CS_Z_LEN];
    r1cs_get_vec_z(r1cs_z , sk , sk+16 );

    uint8_t h_state[PREON_HASH_LEN];
    uint8_t bytes[1] = {1};
    hash_2mesg(h_state,bytes,1,mesg,len_mesg);

    return aurora_generate_proof(sig,r1cs_z,h_state);
}

bool preon_verify( const uint8_t * sig , const uint8_t * pk , const uint8_t * mesg , unsigned len_mesg )
{
    uint8_t r1cs_z[R1CS_Z_LEN];
    r1cs_get_vec_1v(r1cs_z , pk , pk+16 );

    uint8_t h_state[PREON_HASH_LEN];
    uint8_t bytes[1] = {1};
    hash_2mesg(h_state,bytes,1,mesg,len_mesg);

    return aurora_verify_proof(sig,r1cs_z,h_state);
}




