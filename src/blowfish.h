
#ifndef _FISH_BLOWFISH_H_
#define _FISH_BLOWFISH_H_

extern unsigned char *blowfish_encrypt_ecb(unsigned char *buffer, unsigned int bufferl, unsigned char *key, unsigned int keyl, unsigned int *nbufferl);
extern unsigned char *blowfish_decrypt_ecb(unsigned char *buffer, unsigned int bufferl, unsigned char *key, unsigned int keyl);

#endif
