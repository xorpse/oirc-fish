
#include <openssl/dh.h>
#include <openssl/bn.h>

static const unsigned char dh1080_prime[] = {
    0xFB, 0xE1, 0x02, 0x2E, 0x23, 0xD2, 0x13, 0xE8, 0xAC, 0xFA, 0x9A, 0xE8, 0xB9, 0xDF, 0xAD, 0xA3, 0xEA,
    0x6B, 0x7A, 0xC7, 0xA7, 0xB7, 0xE9, 0x5A, 0xB5, 0xEB, 0x2D, 0xF8, 0x58, 0x92, 0x1F, 0xEA, 0xDE, 0x95,
    0xE6, 0xAC, 0x7B, 0xE7, 0xDE, 0x6A, 0xDB, 0xAB, 0x8A, 0x78, 0x3E, 0x7A, 0xF7, 0xA7, 0xFA, 0x6A, 0x2B,
    0x7B, 0xEB, 0x1E, 0x72, 0xEA, 0xE2, 0xB7, 0x2F, 0x9F, 0xA2, 0xBF, 0xB2, 0xA2, 0xEF, 0xBE, 0xFA, 0xC8,
    0x68, 0xBA, 0xDB, 0x3E, 0x82, 0x8F, 0xA8, 0xBA, 0xDF, 0xAD, 0xA3, 0xE4, 0xCC, 0x1B, 0xE7, 0xE8, 0xAF,
    0xE8, 0x5E, 0x96, 0x98, 0xA7, 0x83, 0xEB, 0x68, 0xFA, 0x07, 0xA7, 0x7A, 0xB6, 0xAD, 0x7B, 0xEB, 0x61,
    0x8A, 0xCF, 0x9C, 0xA2, 0x89, 0x7E, 0xB2, 0x8A, 0x61, 0x89, 0xEF, 0xA0, 0x7A, 0xB9, 0x9A, 0x8A, 0x7F,
    0xA9, 0xAE, 0x29, 0x9E, 0xFA, 0x7B, 0xA6, 0x6D, 0xEA, 0xFE, 0xFB, 0xEF, 0xBF, 0x0B, 0x7D, 0x8B
};

#define dh1080_generator "2"

int dh1080_generate_keys(unsigned char **private, unsigned int *private_size, unsigned char **public, unsigned int *public_size)
{
   DH *dh;
   BIGNUM *dh_n = NULL, *dh_g = NULL;

   if (!(dh_n = BN_bin2bn(dh1080_prime, sizeof(dh1080_prime), NULL))) {
      return(0);
   }

   if (!BN_hex2bn(&dh_g, dh1080_generator)) {
      BN_clear_free(dh_n);
      return(0);
   }

   dh    = DH_new();
   dh->g = dh_g;
   dh->p = dh_n;


   if (!DH_generate_key(dh)) {
      DH_free(dh);
      return(0);
   }

   *public_size  = BN_num_bytes(dh->pub_key);
   *private_size = BN_num_bytes(dh->priv_key);

   if (!(*private = malloc(*private_size))) {
      *public_size = *private_size = 0;
      DH_free(dh);
      return(0);
   }

   if (!(*public = malloc(*public_size))) {
      free(*private);
      *public_size = *private_size = 0;
      DH_free(dh);
      return(0);
   }

   *public_size  = BN_bn2bin(dh->pub_key, *public);
   *private_size = BN_bn2bin(dh->priv_key, *private);

   DH_free(dh);
   return(1);
}

int dh1080_compute_key(unsigned char *private, unsigned int private_size, unsigned char *public, unsigned int public_size, unsigned char **shared_key, unsigned int *shared_length)
{
   DH *dh;
   BIGNUM *dh_n = NULL, *dh_g = NULL, *dh_priv = NULL, *dh_pub = NULL;

   if (!(dh_n = BN_bin2bn(dh1080_prime, sizeof(dh1080_prime), NULL))) {
      return(0);
   }

   if (!BN_hex2bn(&dh_g, dh1080_generator)) {
      BN_clear_free(dh_n);
      return(0);
   }

   if (!(dh_priv = BN_bin2bn(private, private_size, NULL))) {
      BN_clear_free(dh_n);
      BN_clear_free(dh_g);
      return(0);
   }

   if (!(dh_pub = BN_bin2bn(public, public_size, NULL))) {
      BN_clear_free(dh_n);
      BN_clear_free(dh_g);
      BN_clear_free(dh_priv);
      return(0);
   }

   dh           = DH_new();
   dh->g        = dh_g;
   dh->p        = dh_n;
   dh->priv_key = dh_priv;

   *shared_length = DH_size(dh);
   if (!(*shared_key = malloc(*shared_length))) {
      BN_clear_free(dh_pub);
      DH_free(dh);
      return(0);
   }

   if ((*shared_length = DH_compute_key(*shared_key, dh_pub, dh)) == -1) {
      free(*shared_key);
      BN_clear_free(dh_pub);
      DH_free(dh);
      return(0);
   }

   DH_free(dh);
   return(1);
}

/*
int main(void)
{
   unsigned int pu_s, pr_s, skl;
   unsigned char *puk, *prk, *s_k;

   if (dh1080_generate_keys(&prk, &pr_s, &puk, &pu_s)) {
      printf("Private key: "); for (int i = 0; i < pr_s; i++) printf("%02X ", prk[i]);
      putchar('\n');
      printf("Public key : "); for (int i = 0; i < pu_s; i++) printf("%02X ", puk[i]);
      putchar('\n');
      
   }

   if (dh1080_compute_key(prk, pr_s, puk, pu_s, &s_k, &skl)) {
      printf("Shared key : "); for (int i = 0; i < skl; i++) printf("%02X ", s_k[i]);
      putchar('\n');
   }

   return(0);
}
*/
