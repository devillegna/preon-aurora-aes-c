#ifndef _AES128R1CS_H_
#define _AES128R1CS_H_

#ifdef  __cplusplus
extern  "C" {
#endif


#include "stdint.h"


#define R1CS_INSTANCE_DIM   6
#define R1CS_WITNESS_IDX   (1<<R1CS_INSTANCE_DIM)

#define R1CS_NCOL   3320
#define R1CS_NROW   3656
#define R1CS_PADLEN 4096

#define R1CS_Z_LEN  (R1CS_NCOL)



void r1cs_get_vec_z( uint8_t * vec_z , const uint8_t * pt , const uint8_t * key );

void r1cs_matA_x_vec_z( uint64_t * Az , const uint8_t * vec_z  );
void r1cs_matB_x_vec_z( uint64_t * Bz , const uint8_t * vec_z  );
void r1cs_matC_x_vec_z( uint64_t * Cz , const uint8_t * vec_z  );

void r1cs_matA_colvec_dot( uint64_t * vec_row , const uint64_t * alphas );
void r1cs_matB_colvec_dot( uint64_t * vec_row , const uint64_t * alphas );
void r1cs_matC_colvec_dot( uint64_t * vec_row , const uint64_t * alphas );


#ifdef  __cplusplus
}
#endif

#endif
