#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "blake2.h"


inline void x13hash(void *output, const void *input)
{
    unsigned char hash1[128];

    memset(hash1, 0, 128);
  
    //uint32_t hash1[16];

    blake2s_state S[1];
    blake2s_init( S, BLAKE2S_OUTBYTES );
    blake2s_update( S, input, 80 );
    blake2s_final( S, hash1, BLAKE2S_OUTBYTES );

    memcpy(output, hash1, 32);

}

int scanhash_x13(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
    uint32_t max_nonce, unsigned long *hashes_done)
{
    uint32_t n = pdata[19] - 1;
    const uint32_t first_nonce = pdata[19];
    const uint32_t Htarg = ptarget[7];

    uint32_t hash64[8] __attribute__((aligned(32)));
    uint32_t endiandata[32];

    //we need bigendian data...
    //lessons learned: do NOT endianchange directly in pdata, this will all proof-of-works be considered as stale from minerd.... 
    int kk=0;
    for (; kk < 32; kk++)
    {
	      be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
    };

    do {
	      pdata[19] = ++n;
	      be32enc(&endiandata[19], n); 
	      x13hash(hash64, &endiandata);
            if (((hash64[7]&0xFFFFFF00)==0) && 
			      fulltest(hash64, ptarget)) {
                *hashes_done = n - first_nonce + 1;
		      return true;
	      }
    } while (n < max_nonce && !work_restart[thr_id].restart);

    *hashes_done = n - first_nonce + 1;
    pdata[19] = n;
    return 0;
}
