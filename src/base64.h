
#ifndef _FISH_BASE64_H_
#define _FISH_BASE64_H_

extern unsigned char *buffer_of_base64(char *b64_buffer, unsigned int *raw_buffer_size);
extern char *base64_of_buffer(unsigned char *raw_buffer, const unsigned int raw_buffer_size, unsigned int *b64_buffer_size);

#endif
