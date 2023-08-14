/// @file utils_hash.h
/// @brief the interface for adapting hash functions.
///
///
#ifndef _UTILS_HASH_H_
#define _UTILS_HASH_H_

#ifdef  __cplusplus
extern  "C" {
#endif


#define HASH_DIGEST_LEN     32

#define _UTILS_OPENSSL_





#if defined(_UTILS_OPENSSL_)||defined(_UTILS_SUPERCOP_)

#include <openssl/evp.h>

typedef struct hash_ctx {
    EVP_MD_CTX *x;
} hash_ctx;

#else
// default
ERROR: openssl implementation only.
#endif


int hash_init( hash_ctx *ctx );

int hash_update( hash_ctx *ctx, const unsigned char *mesg, size_t mlen );

int hash_ctx_copy( hash_ctx *nctx, const hash_ctx *octx );     // nctx needs no hash_init()

int hash_final_digest( unsigned char *digest, hash_ctx *ctx );     // free ctx



static inline void hash_1mesg( unsigned char *digest , const unsigned char *mesg, size_t mlen ) {
    hash_ctx ctx0;
    hash_init( &ctx0 );
    hash_update( &ctx0, mesg, mlen );
    hash_final_digest( digest , &ctx0 );
}

static inline void hash_2mesg( unsigned char *digest , const unsigned char *mesg0, size_t mlen0, const unsigned char *mesg1, size_t mlen1 ) {
    hash_ctx ctx0;
    hash_init( &ctx0 );
    hash_update( &ctx0, mesg0, mlen0 );
    hash_update( &ctx0, mesg1, mlen1 );
    hash_final_digest( digest , &ctx0 );
}

static inline void hash_3mesg( unsigned char *digest , const unsigned char *mesg0, size_t mlen0, const unsigned char *mesg1, size_t mlen1, const unsigned char *mesg2, size_t mlen2 ) {
    hash_ctx ctx0;
    hash_init( &ctx0 );
    hash_update( &ctx0, mesg0, mlen0 );
    hash_update( &ctx0, mesg1, mlen1 );
    hash_update( &ctx0, mesg2, mlen2 );
    hash_final_digest( digest , &ctx0 );
}


#ifdef  __cplusplus
}
#endif



#endif // _UTILS_HASH_H_

