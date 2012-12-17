
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Implementation of base64 encoding function uses no padding, and has no
 * maximum line length (i.e. does not break lines)
 */

#define BASE64_TABLE_SIZE 256

#define BASE64_INIT(TABLE) \
   memset(TABLE, 0, BASE64_TABLE_SIZE); \
   for (int i = 0; i < sizeof(base64_lookup); i++) { \
      TABLE[(unsigned int)base64_lookup[i]] = i; \
   }

#define BASE64_IBUFFER_SIZE(BS) (4 * (BS) / 3 + (4 * (BS) % 3 ? 1 : 0))
#define BASE64_OBUFFER_SIZE(BS) (3 * (BS) / 4 + (3 * (BS) % 4 ? 1 : 0))

/* CONT(INUTE) P(REDICATE) */
#define CONTP(P, DO) \
   if (P) { \
      DO; \
   } else { \
      break; \
   }

#define GET_AT_INDEX(EXP, I, IMAX) (((I) < (IMAX)) ? EXP[I] : 0)
      
const static char base64_lookup[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
//const static char base64_lookup[] = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

unsigned char *buffer_of_base64(char *b64_buffer, unsigned int *raw_buffer_size)
{
   if (!b64_buffer || !raw_buffer_size) {
      return(NULL);
   }

   unsigned char *raw_buffer;
   unsigned char base64_local[BASE64_TABLE_SIZE];
   unsigned int length = strlen(b64_buffer);
   unsigned int i = 0, j = 0;

   BASE64_INIT(base64_local)

   /* Find end of base64 string (could be padded.. */
   for (i = length - 1; i >= 0 && !base64_local[b64_buffer[i]]; i--, length--);

   *raw_buffer_size = BASE64_OBUFFER_SIZE(length);

   if (!(raw_buffer = (unsigned char *)calloc(*raw_buffer_size, sizeof(unsigned char)))) {
      return(NULL);
   }

   for (i = 0, j = 0; ;) {
      CONTP(j + 1 < length, raw_buffer[i]   |= base64_local[b64_buffer[j++]] << 2)
      CONTP(j < length,     raw_buffer[i++] |= base64_local[b64_buffer[j]]   >> 4)
      CONTP(j + 1 < length, raw_buffer[i]   |= base64_local[b64_buffer[j++]] << 4)
      CONTP(j < length,     raw_buffer[i++] |= base64_local[b64_buffer[j]]   >> 2)
      CONTP(j + 1 < length, raw_buffer[i]   |= base64_local[b64_buffer[j++]] << 6)
      CONTP(j < length,     raw_buffer[i++] |= base64_local[b64_buffer[j++]])
   }

   *raw_buffer_size++;
      
   return(raw_buffer);
}

char *base64_of_buffer(unsigned char *raw_buffer, const unsigned int raw_buffer_size, unsigned int *b64_buffer_size)
{

   if (!raw_buffer || !b64_buffer_size) {
      return(NULL);
   }

   char *b64_buffer;
   *b64_buffer_size = BASE64_IBUFFER_SIZE(raw_buffer_size);

   if (!(b64_buffer = (char *)calloc(*b64_buffer_size + 1, sizeof(char)))) {
      return(NULL);
   }

   for (int i = 0, j = 0; i < raw_buffer_size; i += 3) {
      CONTP(j < *b64_buffer_size, \
            b64_buffer[j++] = base64_lookup[GET_AT_INDEX(raw_buffer, i, raw_buffer_size) >> 2]);
      CONTP(j < *b64_buffer_size, \
            b64_buffer[j++] = base64_lookup[GET_AT_INDEX(raw_buffer, i, raw_buffer_size) << 4 & 0x3f | GET_AT_INDEX(raw_buffer, i + 1, raw_buffer_size) >> 4]);
      CONTP(j < *b64_buffer_size, \
            b64_buffer[j++] = base64_lookup[GET_AT_INDEX(raw_buffer, i + 1, raw_buffer_size) << 2 & 0x3f | GET_AT_INDEX(raw_buffer, i + 2, raw_buffer_size) >> 6]);
      CONTP(j < *b64_buffer_size, \
            b64_buffer[j++] = base64_lookup[GET_AT_INDEX(raw_buffer, i + 2, raw_buffer_size) & 0x3f]);
   }

   b64_buffer[*b64_buffer_size] = '\0';
   *b64_buffer_size++;

   return(b64_buffer); /* length + 1 */

}

#undef BASE64_TABLE_SIZE
#undef BASE64_INIT
#undef BASE64_IBUFFER_SIZE
#undef BASE64_OBUFFER_SIZE
#undef CONTP
#undef GET_AT_INDEX
