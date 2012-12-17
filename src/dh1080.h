
#ifndef _FISH_DH1080_H_
#define _FISH_DH1080_H_

extern int dh1080_generate_keys(unsigned char **, unsigned int *, unsigned char **, unsigned int *);
extern int dh1080_compute_key(unsigned char *, unsigned int, unsigned char *, unsigned int, unsigned char **, unsigned int *);

#endif
