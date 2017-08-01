-type result() :: error | binary().

-type aead_algo()           :: aes_gcm | chacha20_poly1305.
-type aead_key()            :: { Algo :: aead_algo(), Key :: binary()}.
-type aead_iv()             :: { Algo :: aead_algo(), IV :: binary()}.
-type aead_plain()          :: { Msg :: binary(), Assoc :: binary()}.
-type aead_cipher()         :: { Algo :: aead_algo(),
				 Assoc :: binary(),
				 IV :: aead_iv(),
				 Ciphertext :: binary(),
				 Authtag  :: binary()}.
-type aead_decrypt_result() :: aead_plain() | error.
-type aead_encrypt_result() :: aead_cipher() | error.
