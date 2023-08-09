/// @file merkeltreecommit.h
/// @brief the interface for merkeltree commit scheme.
///
///
#ifndef _MERKELTREECOMMIT_H_
#define _MERKELTREECOMMIT_H_


#include "utils_hash.h"


#ifdef  __cplusplus
extern  "C" {
#endif


#define MT_RAND_LEN  32

typedef struct merkeltree {
  size_t num_mesg;
  uint8_t * root;
  uint8_t * randomness;
  uint8_t * leaves;
} mt_t;


int mt_init( mt_t * tree , unsigned num_mesg );

void mt_free( mt_t * tree );

int mt_commit( mt_t * tree , const uint8_t * mesgs , unsigned mesg_len , unsigned num_mesg );

#define MT_AUTH_OVERHEAD_LEN( log2_n_mesg )  (MT_RAND_LEN+(log2_n_mesg)*HASH_DIGEST_LEN)

int mt_open( uint8_t * auth_path , const mt_t * tree , const uint8_t *mesg , unsigned mesg_len , unsigned mesg_idx );

int mt_verify( const uint8_t * root , const uint8_t * auth_path , unsigned mesg_len , unsigned num_mesg , unsigned mesg_idx );



#ifdef  __cplusplus
}
#endif



#endif // _UTILS_HASH_H_

