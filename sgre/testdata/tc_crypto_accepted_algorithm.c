/*
 * Crypto-misuse acceptance list (issue #289 T4, pattern 8).
 * MD5 is registered as accepted (non-security use), so its call must not
 * surface a crypto-misuse finding. SHA1 is an unlisted weak algorithm and must
 * still be reported, locking the reverse case.
 */

#include <stdlib.h>

extern void MD5_Update(const void *, unsigned long);
extern void SHA1_Update(const void *, unsigned long);

void tc_crypto_accepted(unsigned long sid)
{
    unsigned char in[8] = {0};
    MD5_Update(in, sid);   /* accepted algorithm: must not report */
    SHA1_Update(in, sid);  /* unlisted weak algorithm: must report */
}
