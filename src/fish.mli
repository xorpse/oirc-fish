

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
