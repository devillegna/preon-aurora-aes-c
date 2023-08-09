
#include "aes128r1cs.h"


///////////////////////////////  XXX: non-constant-time AES implementation  ////////////////////////////

static uint8_t _aes_sbox[] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static uint8_t _aes_rcon[] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

static void _aes128_keyexp( uint8_t *RoundKey, uint8_t *tempas, const uint8_t * key )
{
    //RoundKey = bytearray( 11*16 )
    //tempas = bytearray( 10*4 )

    int Nk = 4;
    int Nb = 4;
    int Nr = 10;
    int tempas_idx = 0;

    //# first round
    //RoundKey[0:16] = key[:]
    for(int i=0;i<16;i++) RoundKey[i] = key[i];

    //for i in range( Nk , Nb*(Nr+1) ):
    for(int i=Nk;i<(Nb*(Nr+1));i++) {
        //tempa = [ RoundKey[ (i-1)*4 + j ] for j in range(4)  ]
        uint8_t tempa[4];  for(int j=0;j<4;j++) tempa[j] = RoundKey[ (i-1)*4+j ];
        if (0 == (i%Nk)) {
            //# rot word
            //tempa[0], tempa[1], tempa[2] , tempa[3] = tempa[1], tempa[2] , tempa[3], tempa[0]
            uint8_t tempa0 = tempa[0];
            tempa[0] = tempa[1]; tempa[1] = tempa[2]; tempa[2] = tempa[3]; tempa[3] = tempa0;
            //# sub word
            //for j in range(4): tempa[j] = _aes_sbox[tempa[j]]
            for(int j=0;j<4;j++) tempa[j] = _aes_sbox[tempa[j]];
            //# add rcon
            //tempa[0] ^= _aes_rcon[i//Nk]
            tempa[0] ^= _aes_rcon[i>>2];
            //# record tempa
            //tempas[tempas_idx:tempas_idx+4] = bytes(tempa)
            for(int j=0;j<4;j++) tempas[tempas_idx+j] = tempa[j];
            tempas_idx += 4;
        }
        //for j in range(4): RoundKey[i*4+j] = RoundKey[ (i-Nk)*4+j ] ^ tempa[j]
        for(int j=0;j<4;j++) RoundKey[i*4+j] = RoundKey[ (i-Nk)*4+j ] ^ tempa[j];
    }
    //return bytes(RoundKey) , bytes(tempas)
}


inline void _add_roundkey( uint8_t * state , const uint8_t * rd_key ) { for(int i=0;i<16;i++) state[i] ^= rd_key[i]; }

inline void _shift_row( uint8_t * state ) {
    uint8_t tmp = state[0+1];
    state[0+1] = state[4+1]; state[4+1] = state[8+1]; state[8+1] = state[12+1]; state[12+1] = tmp;

    uint8_t tmp0 = state[0+2];
    uint8_t tmp1 = state[4+2];
    state[0+2] = state[8+2]; state[4+2] = state[12+2]; state[8+2] = tmp0; state[12+2] = tmp1;

    uint8_t tmpa = state[0+3];
    uint8_t tmpb = state[4+3];
    uint8_t tmpc = state[8+3];
    state[0+3] = state[12+3]; state[4+3] = tmpa; state[8+3] = tmpb; state[12+3] = tmpc;
}

inline uint8_t _x2( uint8_t a ) { return ((a<<1)&0xff)^((a>>7)*0x1b); }
inline uint8_t _x3( uint8_t a ) { return _x2(a)^a; }
//def _mix_col0( a0 , a1, a2 , a3 ): return [_x2(a0)^_x3(a1)^a2^a3, a0^_x2(a1)^_x3(a2)^a3 , a0^a1^_x2(a2)^_x3(a3) , _x3(a0)^a1^a2^_x2(a3)]
inline void _mix_col( uint8_t * state ) {
    for(int i=0;i<4;i++) {
        uint8_t a0 = state[i*4+0];
        uint8_t a1 = state[i*4+1];
        uint8_t a2 = state[i*4+2];
        uint8_t a3 = state[i*4+3];
        state[i*4+0] = _x2(a0)^_x3(a1)^a2^a3;
        state[i*4+1] = _x2(a1)^_x3(a2)^a3^a0;
        state[i*4+2] = _x2(a2)^_x3(a3)^a0^a1;
        state[i*4+3] = _x2(a3)^_x3(a0)^a1^a2;
    }
}

static void _aes128_encrypt( uint8_t *ct , uint8_t *round_state , uint8_t *rk , uint8_t *rk_tmp , const uint8_t *pt , const uint8_t *key ) {
    //rk, rk_tmp = _aes128_keyexp( key )
    _aes128_keyexp( rk, rk_tmp, key );
    //round_state = bytearray( 9*16 )
    //state = bytearray( plain_text )
    uint8_t * state = ct;
    for(int i=0;i<16;i++) state[i]=pt[i];

    int Nr = 10;
    _add_roundkey( state , rk );
    for (int round=1;round<Nr+1;round++) {
        for(int i=0;i<16;i++) state[i] = _aes_sbox[state[i]];
        _shift_row(state);
        if (round == Nr) break;
        _mix_col( state );
        for(int i=0;i<16;i++) round_state[(round-1)*16+i] = state[i];
        _add_roundkey( state , rk+round*16 );
    }
    //# add last roundkey
    _add_roundkey( state , rk+Nr*16 );
    //return bytes( state ), bytes(round_state) , rk , rk_tmp
}



void r1cs_get_vec_z( uint8_t * vec_z , const uint8_t * pt , const uint8_t * key )
{
    vec_z[0] = 1;

    uint8_t round_state[9*16];
    uint8_t rk[11*16];
    uint8_t rk_tmp[10*4];
    _aes128_encrypt( vec_z+1 , round_state , rk , rk_tmp , pt , key );
    for(int i=0;i<16;i++) vec_z[17+i] = pt[i];

    for(int i=1+32;i<R1CS_Z_LEN;i++) vec_z[i]=0;

}










#include "aes128r1cs_mats.data"



void r1cs_matA_x_vec_z( uint64_t * Az , const uint8_t * vec_z  );
void r1cs_matB_x_vec_z( uint64_t * Bz , const uint8_t * vec_z  );
void r1cs_matC_x_vec_z( uint64_t * Cz , const uint8_t * vec_z  );

void r1cs_matA_colvec_dot( uint64_t * vec_row , const uint64_t * alphas );
void r1cs_matB_colvec_dot( uint64_t * vec_row , const uint64_t * alphas );
void r1cs_matC_colvec_dot( uint64_t * vec_row , const uint64_t * alphas );


