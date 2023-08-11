#ifndef _FRILDT_H_
#define _FRILDT_H_

#ifdef  __cplusplus
extern  "C" {
#endif

#include "preon_settings.h"
#include "utils_hash.h"

#define FRI_RS_RHO     RS_RHO

#define FRI_RS_SHIFT   RS_SHIFT

#define FRI_HASH_LEN   HASH_DIGEST_LEN

#define FRI_N_QUERY    26


typedef struct frildt_proof {
//    n_commits = ldt_n_commit( _poly_len )
//    first_commit = proof[0]
    uint8_t * first_commit;
//    commits     = proof[1:1+n_commits]
//    d1poly      = proof[1+n_commits]
//    open_mesgs  = proof[2+n_commits:2+n_commits+n_commits]
//    first_mesgs = proof[2+n_commits+n_commits]
} frildt_proof_t;


#define FRI_GF_BYTELEN   24
#define FRI_POLYLEN      32
#define FRI_LOGPOLYLEN   5

#define FRI_N_MESG       (FRI_POLYLEN/2)
#define FRI_AUTHPATH_LEN (FRI_LOGPOLYLEN-1)

// XXX: fix this
#define FRI_PROOF_SIZE(log_polylen)    (log_polylen*FRI_HASH_LEN + FRI_N_QUERY)



#include "gf2192.h"

//def ldt_commit_phase( vi , poly_len , h_state , RS_rho=8 , RS_shift=1<<63, verbose = 1 ):  return commits , d1poly , mktrees , h_state

//def ldt_query_phase( f_length , mktrees, h_state , Nq , RS_rho=8 , verbose = 1 ):  return open_mesgs , _queries


//def ldt_gen_proof( f0 , h_state , Nq = 26 , RS_rho = 8 , verbose = 1 ):     return proof

int frildt_gen_proof( uint8_t * proof , const gfvec_t *f0, const uint8_t *h_state );

////////////////////////

//def ldt_recover_challenges( _poly_len , h_state , commits , d1poly , Nq , RS_rho = 8 , verbose = 1 ):     return xi , queries

//def ldt_verify_proof( commits , d1poly , first_mesgs , open_mesgs , xi , queries , RS_shift=1<<63 , verbose = 1 ): -> Bool

//def ldt_verify( proof , _poly_len , h_state , Nq = 26 , RS_rho = 8 , verbose = 1 ): -> Bool

int frildt_verify( const uint8_t * proof , unsigned poly_len , const uint8_t *h_state );










#ifdef  __cplusplus
}
#endif

#endif