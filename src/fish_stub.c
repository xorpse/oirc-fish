
#include <string.h>

#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/memory.h>
#include <caml/fail.h>

#include "base64.h"
#include "blowfish.h"
#include "custom_base64.h"
#include "dh1080.h"
#include "sha256.h"

CAMLprim value ml_fish_base64_encode_ns(value input)
{
   CAMLparam1(input);
   CAMLlocal1(edata);

   unsigned int size;
   char *result = \
      cbase64_of_buffer(String_val(input), caml_string_length(input), &size);

   if (result) {
      edata = caml_alloc_string(size - 1);
      memcpy(String_val(edata), result, size - 1);
      free(result);

      CAMLreturn(edata);
   } else {
      caml_failwith("Fish.Base64.encode_ns");
   }
}
      
CAMLprim value ml_fish_base64_decode_ns(value input)
{
   CAMLparam1(input);
   CAMLlocal1(ddata);

   unsigned int size;
   unsigned char *result = \
      buffer_of_cbase64(String_val(input), &size);

   if (result) {
      ddata = caml_alloc_string(size);
      memcpy(String_val(ddata), result, size);
      free(result);

      CAMLreturn(ddata);
   } else {
      caml_failwith("Fish.Base64.decode_ns");
   }
}

CAMLprim value ml_fish_base64_encode_np(value input)
{
   CAMLparam1(input);
   CAMLlocal1(edata);

   unsigned int size;
   char *result = \
      base64_of_buffer(String_val(input), caml_string_length(input), &size);

   if (result) {
      edata = caml_alloc_string(size);
      memcpy(String_val(edata), result, size);
      free(result);

      CAMLreturn(edata);
   } else {
      caml_failwith("Fish.Base64.encode_np");
   }
}
      
CAMLprim value ml_fish_base64_decode_np(value input)
{
   CAMLparam1(input);
   CAMLlocal1(ddata);

   unsigned int size;
   unsigned char *result = \
      buffer_of_base64(String_val(input), &size);

   if (result) {
      ddata = caml_alloc_string(size);
      memcpy(String_val(ddata), result, size);
      free(result);

      CAMLreturn(ddata);
   } else {
      caml_failwith("Fish.Base64.decode_np");
   }
}

CAMLprim value ml_fish_blowfish_encrypt(value key, value data)
{
   CAMLparam2(key, data);
   CAMLlocal1(edata);

   unsigned int size;
   unsigned char *result = \
      blowfish_encrypt_ecb(String_val(data), caml_string_length(data), \
                           String_val(key),  caml_string_length(key), \
                           &size \
                          );

   if (result) {
      edata = caml_alloc_string(size);
      memcpy(String_val(edata), result, size);
      free(result);

      CAMLreturn(edata);
   } else {
      caml_failwith("Fish.Blowfish.encrypt");
   }
}

CAMLprim value ml_fish_blowfish_decrypt(value key, value data)
{
   CAMLparam2(key, data);
   CAMLlocal1(ddata);

   unsigned int size = caml_string_length(data);
   unsigned char *result = \
      blowfish_decrypt_ecb(String_val(data), size, \
                           String_val(key),  caml_string_length(key) \
                          );

   if (result) {
      ddata = caml_alloc_string(size);
      memcpy(String_val(ddata), result, size);
      free(result);

      CAMLreturn(ddata);
   } else {
      caml_failwith("Fish.Blowfish.decrypt");
   }
}

CAMLprim value ml_fish_dh1080_generate(value unit)
{
   CAMLparam1(unit);
   CAMLlocal3(pr_k, pu_k, ks);

   unsigned int pr_s, pu_s;
   unsigned char *pr, *pu;

   if (dh1080_generate_keys(&pr, &pr_s, &pu, &pu_s)) {
      pr_k = caml_alloc_string(pr_s);
      memcpy(String_val(pr_k), pr, pr_s);
      memset(pr, 0, pr_s);
      free(pr); 

      pu_k = caml_alloc_string(pu_s);
      memcpy(String_val(pu_k), pu, pu_s);
      memset(pu, 0, pu_s);
      free(pu);

      ks = caml_alloc(2, 0);

      Store_field(ks, 0, pr_k);
      Store_field(ks, 1, pu_k);

      CAMLreturn(ks);
   } else {
      caml_failwith("Fish.DH1080.generate");
   }
}

CAMLprim value ml_fish_dh1080_compute(value priv, value pub)
{
   CAMLparam2(priv, pub);
   CAMLlocal1(shared);

   unsigned int sh_s;
   unsigned char *sh_k;

   if (dh1080_compute_key(String_val(priv), caml_string_length(priv), String_val(pub), caml_string_length(pub), &sh_k, &sh_s)) {
      shared = caml_alloc_string(sh_s);
      memcpy(String_val(shared), sh_k, sh_s);
      memset(sh_k, 0, sh_s);
      free(sh_k);

      CAMLreturn(shared);
   } else {
      caml_failwith("Fish.DH1080.compute");
   }
}

CAMLprim value ml_fish_sha256_compute(value input)
{
   CAMLparam1(input);
   CAMLlocal1(hash);

   hash = caml_alloc_string(SHA256_BUFFER_SIZE);

   if (sha256(String_val(input), caml_string_length(input), String_val(hash))) {
      CAMLreturn(hash);
   } else {
      caml_failwith("Fish.SHA256.compute");
   }
}
