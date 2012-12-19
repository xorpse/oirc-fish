
#include <openssl/sha.h>

unsigned char *sha256(unsigned char *buf, unsigned int len, unsigned char *hash)
{
   if (!buf || !hash) {
      return(NULL);
   }

   return(SHA256(buf, len, hash));
}
