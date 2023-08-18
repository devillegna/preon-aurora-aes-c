#ifndef _AURORA_H_
#define _ARRORA_H_

#ifdef  __cplusplus
extern  "C" {
#endif


#include "preon_settings.h"

#include "stdint.h"


int aurora_generate_proof( uint8_t * proof , const uint8_t * r1cs_z , const uint8_t * h_state);

int aurora_verify_proof( const uint8_t * proof , const uint8_t * r1cs_z , const uint8_t * h_state );



#ifdef  __cplusplus
}
#endif

#endif
