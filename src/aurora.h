#ifndef _AURORA_H_
#define _AURORA_H_

#ifdef  __cplusplus
extern  "C" {
#endif


#include "preon_settings.h"

#include "stdint.h"


#include "merkeltreecommit.h"


#define R1CS_POLYLEN        4096
#define R1CS_LOGPOLYLEN     12

#define AURORA_POLYLEN      (1<<13)
#define AURORA_LOGPOLYLEN   13


#define AURORA_MT_MESG0_LEN  (GF_BYTES*2*4)
#define AURORA_MT_MESG1_LEN  (GF_BYTES*2)
#define AURORA_MT_N_MESG    (RS_RHO*AURORA_POLYLEN/2)
#define AURORA_MT_LOGMESG   (RS_LOGRHO+AURORA_LOGPOLYLEN-1)


#include "frildt.h"
#if AURORA_POLYLEN != FRI_POLYLEN
error -> inconsistent POLYLEN
#endif

typedef struct _aurora_proof_ {
    const uint8_t * commit0;
    const uint8_t * commit1;
    const uint8_t * fri_commits[FRI_CORE_N_COMMITS];
    const uint8_t * fri_d1poly;
    const uint8_t * fri_open_mesgs[FRI_CORE_N_COMMITS];
    const uint8_t * open_mesgs0;
    const uint8_t * open_mesgs1;
} aurora_proof_t;

static inline
void aurora_proof_setptr( aurora_proof_t * prf_ptr , const uint8_t * prf )
{
//    const uint8_t * backup = prf;
//    prf_ptr->first_commit = prf;       prf += FRI_HASH_LEN;
//    for(int i=0;i<FRI_CORE_N_COMMITS;i++) {
//        prf_ptr->commits[i] = prf;     prf += FRI_HASH_LEN;
//    }
//    prf_ptr->d1poly = prf;             prf += 2*FRI_GF_BYTES;
//    frildt_setptr_openmesgs( prf_ptr->open_mesgs , prf );   prf += FRI_CORE_OPEN_LEN;
//    prf_ptr->first_mesgs = prf;        prf += FRI_N_QUERY * MT_AUTHPATH_LEN( FRI_MT_MESG_LEN , FRI_MT_LOGMESG );
//    return prf-backup;
}









int aurora_generate_proof( uint8_t * proof , const uint8_t * r1cs_z , const uint8_t * h_state);

int aurora_verify_proof( const uint8_t * proof , const uint8_t * r1cs_z , const uint8_t * h_state );



#ifdef  __cplusplus
}
#endif

#endif
