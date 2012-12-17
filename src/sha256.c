#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openssl/sha.h>
#include "sha256.h"

unsigned char *sha256(unsigned char *buf, unsigned int len, unsigned char *hash)
{
   if (!buf || !hash) {
      return(NULL);
   }

   return(SHA256(buf, len, hash));
}
