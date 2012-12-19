#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const static unsigned char cbase64_lookup[]= "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

const static unsigned char cbase64_rlookup[] = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\xff\xff\xff\xff\xff\xff\xff\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\xff\xff\xff\xff\xff\xff\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";

#define BSWAP32(I) (I) << 24 | (I) >> 24 | (I) << 8 & 0x00FF0000 | (I) >> 8 & 0x0000FF00

char *cbase64_of_buffer(unsigned char *buffer, const unsigned int length, unsigned int *size)
{
   if (!buffer || length % 8 || !size) {
      return(NULL);
   }

   unsigned int temp1, temp2;
   char *buff, *ptr;
   *size = length + (length >> 1) + 1;

   if(!(buff = calloc(*size, sizeof(char)))) {
      return(NULL);
   }

   ptr = buff;

   for (int i = 0; i < length >> 2; i += 2) {
      temp1 = *((unsigned int *)buffer + i);
      temp2 = *((unsigned int *)buffer + i + 1);

      temp1 = BSWAP32(temp1);
      temp2 = BSWAP32(temp2);

      for (int j = 0; j < 6; j++, temp2 >>= 6) {
         *ptr++ = cbase64_lookup[temp2 & 0x3f];
      }

      for (int j = 0; j < 6; j++, temp1 >>= 6) {
         *ptr++ = cbase64_lookup[temp1 & 0x3f];
      }

   }

   *ptr = '\0';
   return(buff);
}

unsigned char *buffer_of_cbase64(char *b64_buffer, unsigned int *size)
{
   unsigned int bl;

   if (!b64_buffer || !size || (bl = strlen(b64_buffer)) % 12) {
      return(NULL);
   }

   unsigned char *temp1, *temp2;
   unsigned char *buff, *ptr;

   *size = (bl << 1) / 3;

   if (!(buff = calloc(*size, sizeof(unsigned char)))) {
      return(NULL);
   }

   ptr = buff;

   for (int i = 0; i < *size >> 2; i+=2) {
      temp1 = b64_buffer + (i * 6);
      temp2 = temp1 + 6;

      for (int j = 0; j < 6; j++) {
         *((unsigned int *)ptr) |= cbase64_rlookup[temp2[j]] << (j * 6);
      }
      ptr += 4;

      for (int j = 0; j < 6; j++) {
         *((unsigned int *)ptr) |= cbase64_rlookup[temp1[j]] << (j * 6);
      }
      ptr += 4;

      *((unsigned int *)(ptr - 8)) = BSWAP32(*((unsigned int *)(ptr - 8)));
      *((unsigned int *)(ptr - 4)) = BSWAP32(*((unsigned int *)(ptr - 4)));
   }

   *ptr = '\0';
   return(buff);
      
}

#undef BSWAP32
