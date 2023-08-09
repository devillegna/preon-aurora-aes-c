/// @file utils_hash.c
/// @brief the adapter for hash functions.
///
///

#include "utils_hash.h"


#if defined(_UTILS_OPENSSL_)||defined(_UTILS_SUPERCOP_)

#include <openssl/evp.h>


int hash_init( hash_ctx *ctx ) {
    ctx->x = EVP_MD_CTX_create();
    if (!ctx->x) {
        return -1;
    }
#if 32 == HASH_DIGEST_LEN
    int ok = EVP_DigestInit_ex(ctx->x, EVP_sha3_256(), NULL);
#elif 64 == HASH_DIGEST_LEN
    int ok = EVP_DigestInit_ex(ctx->x, EVP_sha3_512(), NULL);
#else
ERROR: HASH_GIEST_LEN no matches
#endif
    return (ok) ? 0 : -1;
}

int hash_update( hash_ctx *ctx, const unsigned char *mesg, size_t mlen ) {
    int ok = EVP_DigestUpdate(ctx->x, mesg, mlen);
    return (ok) ? 0 : -1;
}

int hash_ctx_copy( hash_ctx *nctx, const hash_ctx *octx ) {
    nctx->x = EVP_MD_CTX_create();
    if (!nctx->x) {
        return -1;
    }
    int ok = EVP_MD_CTX_copy(nctx->x, octx->x);
    return (ok) ? 0 : -1;
}

int hash_final_digest( unsigned char *out, hash_ctx *ctx ) {
    int ok = EVP_DigestFinal(ctx->x, out, NULL);
    EVP_MD_CTX_destroy(ctx->x);
    return (ok) ? 0 : -1;
}

#endif

