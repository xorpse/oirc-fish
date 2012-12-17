
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/blowfish.h>
#include "custom_base64.h"

unsigned char *blowfish_encrypt_ecb(unsigned char *buffer, unsigned int bufferl, unsigned char *key, unsigned int keyl, unsigned int *nbufferl)
{
   if (!buffer || !key || !nbufferl) {
      return(NULL);
   }

   unsigned char *nbuffers, *nbufferd;
   *nbufferl = bufferl + (bufferl % 8 ? (8 - bufferl % 8) : 0);

   BF_KEY bf_key;

   if (!(nbuffers = calloc(*nbufferl, sizeof(unsigned char)))) {
      return(NULL);
   }

   if (!(nbufferd = calloc(*nbufferl, sizeof(unsigned char)))) {
      free(nbuffers);
      return(NULL);
   }

   BF_set_key(&bf_key, keyl, key);
   memcpy(nbuffers, buffer, bufferl);
   memcpy(nbufferd, nbuffers, *nbufferl);

   for (int i = 0; i < *nbufferl; i += 8) {
      BF_ecb_encrypt(nbuffers + i, nbufferd + i, &bf_key, BF_ENCRYPT);
   }

   free(nbuffers);

   return(nbufferd);
}

unsigned char *blowfish_decrypt_ecb(unsigned char *buffer, unsigned int bufferl, unsigned char *key, unsigned int keyl)
{
   if (!buffer || !key || bufferl % 8) {
      return(NULL);
   }

   unsigned char *nbuffer;
   BF_KEY bf_key;

   if (!(nbuffer = calloc(bufferl, sizeof(unsigned char)))) {
      return(NULL);
   }

   BF_set_key(&bf_key, keyl, key);
   memcpy(nbuffer, buffer, bufferl);

   for (int i = 0; i < bufferl; i += 8) {
      BF_ecb_encrypt(buffer + i, nbuffer + i, &bf_key, BF_DECRYPT);
   }

   return(nbuffer);
}

/* EXAMPLE USAGE 
int main(void)
{
   unsigned int inps = 0;

   unsigned char key[] = "abcdefghijklmnopqrstuvwxyz012345";

   unsigned char *buffer = blowfish_encrypt_ecb("Hello, World", 12, key, 32, &inps);
   unsigned char buffer2[1024];

   for (int i = 0; i < inps; i++) {
      printf("%02X ", buffer[i]);
   }

   printf("%s\n", cbase64_of_buffer(buffer, inps, &(int){0}));

   return(0);
}
*/
