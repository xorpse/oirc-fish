

module Base64 : sig

   val encode_np : string -> string
   val decode_np : string -> string

   val encode_ns : string -> string
   val decode_ns : string -> string

end

module Blowfish : sig

   val encrypt : string -> string -> string
   val decrypt : string -> string -> string

end

module DH1080 : sig

   val generate : unit -> (string * string)
   val compute  : string -> string -> string

end

module SHA256 : sig

   val compute : string -> string

end

module Protocol : sig

   type key_pair

   val init_key_exchange  : string -> (key_pair * Scmd.t)
   val process_dh_message : key_pair option -> Scmd.t -> (string * Scmd.t option)

   val send_message : string -> string -> string -> Scmd.t
   val recv_message : string -> Scmd.t -> Scmd.t

end
