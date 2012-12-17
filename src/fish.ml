

module Base64 = struct

   let pad_to_mul_of n s =
      let len = String.length s in
      if len mod n <> 0 then
         (s ^ (String.make (8 - len mod n) '\x00'))
      else
         s

   let sequence_of seq s =
      String.iter (fun c -> if not (String.contains seq c) then raise Not_found) s

   external encode_np    : string -> string = "ml_fish_base64_encode_np"
   external decode_np_nv : string -> string = "ml_fish_base64_decode_np"

   let decode_np s =
      let sc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" in
      try
         sequence_of sc s;
         decode_np_nv s
      with
         | Not_found -> raise (Failure "Fish.Base64.decode_np")

   external encode_ns_nv : string -> string = "ml_fish_base64_encode_ns"
   external decode_ns_nv : string -> string = "ml_fish_base64_decode_ns"

   let encode_ns s = encode_ns_nv (pad_to_mul_of 8 s)

   let decode_ns s =
      let sc = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" in
      try
         sequence_of sc s;
         decode_ns_nv s
      with
         | Not_found -> raise (Failure "Fish.Base64.decode_np")

end

module Blowfish = struct

   external encrypt : string -> string -> string = "ml_fish_blowfish_encrypt"
   external decrypt : string -> string -> string = "ml_fish_blowfish_decrypt"

end

module DH1080 = struct

   external generate : unit -> (string * string) = "ml_fish_dh1080_generate"
   external compute  : string -> string -> string = "ml_fish_dh1080_compute"

end

module SHA256 = struct

   external compute : string -> string = "ml_fish_sha256_compute"

end
