
#include "aes128r1cs.h"






void r1cs_get_vec_z( uint8_t * vec_z , const uint8_t * pt , const uint8_t * key );










#include "aes128r1cs_mats.data"


void r1cs_matA_x_vec_z( uint64_t * Az , const uint8_t * vec_z  );
void r1cs_matB_x_vec_z( uint64_t * Bz , const uint8_t * vec_z  );
void r1cs_matC_x_vec_z( uint64_t * Cz , const uint8_t * vec_z  );

void r1cs_matA_colvec_dot( uint64_t * vec_row , const uint64_t * alphas );
void r1cs_matB_colvec_dot( uint64_t * vec_row , const uint64_t * alphas );
void r1cs_matC_colvec_dot( uint64_t * vec_row , const uint64_t * alphas );


