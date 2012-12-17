
#ifndef _FISH_CBASE64_H_
#define _FISH_CBASE64_H_

extern char *cbase64_of_buffer(unsigned char *buffer, const unsigned int length, unsigned int *size);
extern unsigned char *buffer_of_cbase64(char *b64_buffer, unsigned int *size);

#endif
