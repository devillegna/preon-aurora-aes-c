/// @file utils_hash.h
/// @brief the interface for adapting hash functions.
///
///
#ifndef _UTILS_HASH_H_
#define _UTILS_HASH_H_


#define HASH_DIGEST_LEN     32



#define _UTILS_OPENSSL_

#ifdef  __cplusplus
extern  "C" {
#endif


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


#ifdef  __cplusplus
}
#endif



#endif // _UTILS_HASH_H_

