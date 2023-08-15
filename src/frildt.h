#ifndef _FRILDT_H_
#define _FRILDT_H_

#ifdef  __cplusplus
extern  "C" {
#endif

#include "preon_settings.h"
#include "utils_hash.h"
#include "merkeltreecommit.h"


#define FRI_RS_RHO     RS_RHO
#define FRI_RS_LOGRHO  RS_LOGRHO
#define FRI_RS_SHIFT   RS_SHIFT

#define FRI_HASH_LEN   HASH_DIGEST_LEN

//#define FRI_N_QUERY    26
#define FRI_N_QUERY    1


#define FRI_POLYLEN      32
#define FRI_LOGPOLYLEN   5
#define FRI_GF_BYTES     GF_BYTES
#define FRI_GF_NUMU64    (GF_BYTES/sizeof(uint64_t))

#define FRI_MT_MESG_LEN  (FRI_GF_BYTES*2)
#define FRI_MT_N_MESG    (FRI_RS_RHO*FRI_POLYLEN/2)
#define FRI_MT_LOGMESG   (FRI_RS_LOGRHO+FRI_LOGPOLYLEN-1)

#define FRI_N_COMMIT        (FRI_LOGPOLYLEN-1)

#define FRI_CORE_N_COMMITS  (FRI_LOGPOLYLEN-2)
#define FRI_CORE_OPEN_LEN   (FRI_N_QUERY*(FRI_CORE_N_COMMITS)*(MT_AUTHPATH_LEN(FRI_MT_MESG_LEN,FRI_MT_LOGMESG-FRI_CORE_N_COMMITS)+MT_AUTHPATH_LEN(FRI_MT_MESG_LEN,FRI_MT_LOGMESG-1))/2)
#define FRI_CORE_LEN        (FRI_CORE_N_COMMITS*FRI_HASH_LEN + FRI_GF_BYTES*2 + FRI_CORE_OPEN_LEN )

#define FRI_PROOF_LEN    (FRI_HASH_LEN + FRI_CORE_LEN + FRI_N_QUERY*MT_AUTHPATH_LEN( FRI_MT_MESG_LEN , FRI_MT_LOGMESG ))

typedef struct _frildt_proof_ {
    unsigned n_commits;
    uint8_t * first_commit;
    uint8_t * commits[FRI_CORE_N_COMMITS];
    uint8_t * d1poly;
    uint8_t * open_mesgs[FRI_CORE_N_COMMITS];
    uint8_t * first_mesgs;
//    n_commits = ldt_n_commit( _poly_len )
//    first_commit = proof[0]
//    commits     = proof[1:1+n_commits]
//    d1poly      = proof[1+n_commits]
//    open_mesgs  = proof[2+n_commits:2+n_commits+n_commits]
//    first_mesgs = proof[2+n_commits+n_commits]
} frildt_proof_t;

static inline
size_t frildt_proof_setptr( frildt_proof_t * prf_ptr , uint8_t * prf )
{
    prf_ptr->n_commits = FRI_CORE_N_COMMITS;
    uint8_t * backup = prf;
    prf_ptr->first_commit = prf;       prf += FRI_HASH_LEN;
    for(int i=0;i<FRI_CORE_N_COMMITS;i++) {
        prf_ptr->commits[i] = prf;     prf += FRI_HASH_LEN;
    }
    prf_ptr->d1poly = prf;             prf += 2*FRI_GF_BYTES;
    for(int i=0;i<FRI_CORE_N_COMMITS;i++) {
        prf_ptr->open_mesgs[i] = prf;  prf += FRI_N_QUERY * MT_AUTHPATH_LEN( FRI_MT_MESG_LEN , FRI_MT_LOGMESG-(i+1) );
    }
    prf_ptr->first_mesgs = prf;        prf += FRI_N_QUERY * MT_AUTHPATH_LEN( FRI_MT_MESG_LEN , FRI_MT_LOGMESG );
    return prf-backup;
}



#include "gfvec.h"

//def ldt_commit_phase( vi , poly_len , h_state , RS_rho=8 , RS_shift=1<<63, verbose = 1 ):  return commits , d1poly , mktrees , h_state

int frildt_commit_phase( uint8_t * proof , mt_t mts[] , gfvec_t mesgs[], gfvec_t v0 ,  unsigned poly_len , uint8_t *h_state );

//def ldt_query_phase( f_length , mktrees, h_state , Nq , RS_rho=8 , verbose = 1 ):  return open_mesgs , _queries

void frildt_get_queries( uint32_t * queries , const uint8_t * h_state );

void frildt_query_phase( uint8_t * proof , mt_t mktrees[] , gfvec_t mesgs[], const uint32_t * queries );

//def ldt_gen_proof( f0 , h_state , Nq = 26 , RS_rho = 8 , verbose = 1 ):     return proof

int frildt_gen_proof( uint8_t * proof , const gfvec_t *f0, const uint8_t *h_state );

////////////////////////

//def ldt_recover_challenges( _poly_len , h_state , commits , d1poly , Nq , RS_rho = 8 , verbose = 1 ):     return xi , queries

void frildt_recover_challenges( uint32_t * queries , uint64_t *d1poly , uint64_t *xi , const uint8_t *h_state , const uint8_t * proof );

//def ldt_verify_proof( commits , d1poly , first_mesgs , open_mesgs , xi , queries , RS_shift=1<<63 , verbose = 1 ): -> Bool

int frildt_verify_commit_open( const uint8_t * commits , const uint8_t * open_mesgs , const uint32_t * queries );

//int frildt_verify_linear_relation(  )

//def ldt_verify( proof , _poly_len , h_state , Nq = 26 , RS_rho = 8 , verbose = 1 ): -> Bool

int frildt_verify( const uint8_t * proof , unsigned poly_len , const uint8_t *h_state );










#ifdef  __cplusplus
}
#endif

#endif
