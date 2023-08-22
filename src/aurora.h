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

#define AURORA_MT_MESG0_LEN  (GF_BYTES*2*6)
#define AURORA_MT_MESG1_LEN  (GF_BYTES*2)
#define AURORA_MT_N_MESG     (RS_RHO*AURORA_POLYLEN/2)
#define AURORA_MT_LOGMESG    (RS_LOGRHO+AURORA_LOGPOLYLEN-1)


#include "frildt.h"
#if AURORA_POLYLEN != FRI_POLYLEN
error -> inconsistent POLYLEN
#endif

#define AURORA_PROOF_LEN     (PREON_HASH_LEN*2 + FRI_CORE_LEN + FRI_N_QUERY*MT_AUTHPATH_LEN( AURORA_MT_MESG0_LEN,AURORA_MT_LOGMESG) + FRI_N_QUERY*MT_AUTHPATH_LEN( AURORA_MT_MESG1_LEN,AURORA_MT_LOGMESG) )


typedef struct _aurora_proof_ {
    const uint8_t * commit0;
    const uint8_t * commit1;
    const uint8_t * fri_proof;
    const uint8_t * open_mesgs0;
    const uint8_t * open_mesgs1;
} aurora_proof_t;

static inline
void aurora_proof_setptr( aurora_proof_t * prf_ptr , const uint8_t * prf )
{
    prf_ptr->commit0 = prf;       prf += PREON_HASH_LEN;
    prf_ptr->commit1 = prf;       prf += PREON_HASH_LEN;
    prf_ptr->fri_proof = prf;     prf += FRI_CORE_LEN;
    prf_ptr->open_mesgs0 = prf;   prf += FRI_N_QUERY * MT_AUTHPATH_LEN( AURORA_MT_MESG0_LEN , AURORA_MT_LOGMESG );
    prf_ptr->open_mesgs1 = prf;
}



int aurora_generate_proof( uint8_t * proof , const uint8_t * r1cs_z , const uint8_t * h_state);

#include "stdbool.h"

bool aurora_verify_proof( const uint8_t * proof , const uint8_t * r1cs_z , const uint8_t * h_state );



#ifdef  __cplusplus
}
#endif

#endif
