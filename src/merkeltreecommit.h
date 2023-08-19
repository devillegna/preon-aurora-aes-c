/// @file merkeltreecommit.h
/// @brief the interface for merkeltree commit scheme.
///
///
#ifndef _MERKELTREECOMMIT_H_
#define _MERKELTREECOMMIT_H_

#ifdef  __cplusplus
extern  "C" {
#endif




#include "utils_hash.h"


#define MT_RAND_LEN  32

#define MT_AUTH_OVERHEAD_LEN( log_n_mesg )         (MT_RAND_LEN+(log_n_mesg)*HASH_DIGEST_LEN)

#define MT_AUTHPATH_LEN( mesg_len , log_n_mesg )   (mesg_len+(MT_AUTH_OVERHEAD_LEN(log_n_mesg)))


typedef struct merkeltree {
  uint8_t * root;
  uint8_t * randomness;
  uint8_t * leaves;
  unsigned  num_mesg;
} mt_t;


int mt_init( mt_t * tree , unsigned num_mesg );

void mt_free( mt_t * tree );

int mt_commit( mt_t tree , const uint8_t * mesgs , unsigned mesg_len , unsigned num_mesg );

void mt_open( uint8_t * auth_path , const mt_t tree , const uint8_t *mesg , unsigned mesg_len , unsigned mesg_idx );

static inline
void mt_batchopen( uint8_t * auth_path , const mt_t tree , const uint8_t *mesgs , unsigned mesg_len , uint32_t mesg_idx[] , unsigned n_idx ) {
  unsigned tree_log_n_mesg = __builtin_ctz(tree.num_mesg);
  unsigned auth_len = MT_AUTHPATH_LEN( mesg_len , tree_log_n_mesg );
  for(unsigned i=0;i<n_idx;i++){
    mt_open( auth_path , tree , mesgs+mesg_len*mesg_idx[i] , mesg_len , mesg_idx[i] );
    auth_path += auth_len;
  }
}


#include "stdbool.h"

bool mt_verify( const uint8_t * root , const uint8_t * auth_path , unsigned mesg_len , unsigned num_mesg , unsigned mesg_idx );

static inline
bool mt_batchverify( const uint8_t * root , const uint8_t * auth_path , unsigned mesg_len , unsigned num_mesg , unsigned mesg_idx[] , unsigned n_idx ) {
  unsigned log_n_mesg = __builtin_ctz(num_mesg);
  unsigned auth_len = MT_AUTHPATH_LEN( mesg_len , log_n_mesg );
  for(unsigned i=0;i<n_idx;i++){
    int ri = mt_verify( root , auth_path , mesg_len , num_mesg , mesg_idx[i] );
    auth_path += auth_len;
    if (!ri) return false;
  }
  return true;
}




#ifdef  __cplusplus
}
#endif

#endif // _UTILS_HASH_H_

