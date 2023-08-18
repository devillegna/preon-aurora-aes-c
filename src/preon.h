#ifndef _PREON_H_
#define _PREON_H_

#ifdef  __cplusplus
extern  "C" {
#endif


#include "preon_settings.h"

#include "stdint.h"


int preon_keygen( uint8_t * pk , uint8_t * sk );

int preon_sign( uint8_t * sig , const uint8_t * sk , const uint8_t * mesg , unsigned len_mesg );

int preon_verify( const uint8_t * sig , const uint8_t * pk , const uint8_t * mesg , unsigned len_mesg );



#ifdef  __cplusplus
}
#endif

#endif
