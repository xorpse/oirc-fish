
let () =
   String.iter (fun c -> Printf.printf "%02x" (int_of_char c)) (Fish.SHA256.compute "");
   let key = "some_key:))" in
   print_endline (Fish.Blowfish.decrypt key (Fish.Blowfish.encrypt key "Hello, World"));
   print_endline (Fish.Base64.decode_ns (Fish.Base64.encode_ns "Hello, World!"));
   let priv, pub = Fish.DH1080.generate () in
   print_endline (Fish.Base64.encode_np priv);
   print_endline (Fish.Base64.encode_np pub);
   let secret = Fish.DH1080.compute priv pub in
   print_endline (Fish.Base64.encode_np secret)

