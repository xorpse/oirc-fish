

module Base64 = struct

   let pad_to_mul_of n s =
      let len = String.length s in
      if len mod n <> 0 then
         (s ^ (String.make (n - len mod n) '\x00'))
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

module Protocol = struct

   type key_pair = {
      mutable pr_k : string;
      mutable pu_k : string;
   }

   let zero_string s =
      for i = 0 to (String.length s - 1) do
         String.set s i '\x00'
      done

   let message_to_text s =
      try
         String.sub s 0 (String.index s '\x00')
      with
         | Invalid_argument _
         | Not_found -> s

   let purge_keys { pr_k = pr_k; pu_k = pu_k } =
      zero_string pr_k;
      zero_string pu_k

   let dh_init_msg target key =
      Scmd.MSG_NOTICE (target, ("DH1080_INIT " ^ (Base64.encode_np key)))

   let dh_finish_msg target key =
      Scmd.MSG_NOTICE (target, ("DH1080_FINISH " ^ (Base64.encode_np key)))
   
   let dh_init_key_exchange target =
      try
         let pr, pu = DH1080.generate () in
         ({ pr_k = pr; pu_k = pu}, dh_init_msg target pu)
      with
         | Failure _ -> raise (Failure "Fish.Protocol.dh_init_key_exchange")

   let prepare_key key =
      try
         Base64.encode_np (SHA256.compute key)
      with
         | Failure _ -> raise (Failure "Fish.Protocol.prepare_key")

   let dh_process_message keys = function
      | Scmd.MSG_NOTICE (target, notice) ->
            let dh_init   = Str.regexp "^DH1080_INIT\\ .*$"
            and dh_finish = Str.regexp "^DH1080_FINISH\\ .*$" in

            (try
               let keys, message, oth_pub =
                  if (Str.string_match dh_init notice 0) then
                     let pr, pu = DH1080.generate () in
                     let keys = { pr_k = pr; pu_k = pu } in
                     (keys, Some (dh_finish_msg target pu), String.sub notice 12 (String.length notice - 12))
                  
                  else if (Str.string_match dh_finish notice 0) then
                     let kp = match keys with
                        | None -> raise (Failure "Fish.Protocol.dh_process_message")
                        | Some kp -> kp
                     in
                     (kp, None, String.sub notice 14 (String.length notice - 14))

                  else
                     raise (Invalid_argument "Fish.Protocol.dh_process_message")
               in

               (* Fix for key exchange with FiSH 10 implementation using DH1080_INIT <KEY> CBC *)
               let oth_pub =
                  try
                     String.sub oth_pub 0 (String.index ' ')
                  with
                     | Not_found -> oth_pub
               in

               let sk = DH1080.compute keys.pr_k (Base64.decode_np oth_pub) in
               purge_keys keys;
               (prepare_key sk, message)
            with
               | Failure _
               | Invalid_argument _ -> raise (Failure "Fish.Protocol.dh_process_message")
            )

      | _ -> raise (Invalid_argument "Fish.Protocol.dh_process_message")

   let send_message who key message =
      try
         Scmd.MSG_PRIVMSG (who, ("+OK " ^ (Base64.encode_ns (Blowfish.encrypt key message))))
      with
         | Failure _ -> raise (Failure "Fish.Protocol.send_message")

   let recv_message key = function
      | Scmd.MSG_PRIVMSG (who, msg) ->
            (try
               if (Str.string_match (Str.regexp "^\\+OK\\ .*$") msg 0) then
                  let rm = Base64.decode_ns (String.sub msg 4 (String.length msg - 4)) in
                  Scmd.MSG_PRIVMSG (who, message_to_text (Blowfish.decrypt key rm))
               else
                  raise (Invalid_argument "Fish.Protocol.recv_message")
            with
               | Failure _
               | Invalid_argument _ -> raise (Failure "Fish.Protocol.recv_message")
            )
      | _ -> raise (Invalid_argument "Fish.Protocol.recv_message")

end
