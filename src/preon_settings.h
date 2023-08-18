#ifndef _PREON_SETTINGS_H_
#define _PREON_SETTINGS_H_


#define _PREON_128_
#define _VARIANT_A_

#if defined(_PREON_128_)

#define GF_BITS     192

#define PREON_AESKEYLEN  16
#define PREON_PKLEN     32
#define PREON_SKLEN     (16+PREON_AESKEYLEN)
#define PREON_SIGLEN    16


#define PREON_HASH_LEN  32

#if defined(_VARIANT_A_)
#define PREON_N_QUERY 26
#elif defined(_VARIANT_B_)
#define PREON_N_QUERY  ??
#else
error : no supported
#endif  // variants

#else

error : no implemented

#endif  // security level







#define GF_BYTES    (GF_BITS/8)
#define GF_NUMU64   ((GF_BYTES+7)>>3)



#define RS_RHO      32
#define RS_LOGRHO   5
#define RS_SHIFT    0x8000000000000000



#endif
