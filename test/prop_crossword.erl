-module(prop_crossword).

-include_lib("proper/include/proper.hrl").

aead_algo() -> oneof([aes_gcm, chacha20_poly1305]).
   
prop_aead_generation() ->
  ?FORALL({Algo},{aead_algo()},
	  begin
	    KK={Algo,K} = crossword:aead_key(Algo),
	    II={Algo,I} = crossword:aead_iv(Algo),
	    KS = byte_size(K),
	    IS = byte_size(I),
	    KL = crossword:aead_key_length(Algo),
	    IL = crossword:aead_iv_length(Algo),
	    crossword:aead_key_valid(KK) andalso
	      crossword:aead_iv_valid(II) andalso
	      KL =:= KS andalso IL =:= IS
	  end).

prop_aead_encryption() ->
  ?FORALL({Algo, Plain, Assoc},{aead_algo(), binary(), binary()},
	  begin
	    K = crossword:aead_key(Algo),
	    I = crossword:aead_iv(Algo),
	    Enc = crossword:aead_encrypt(K,I,{Plain,Assoc}),
	    Enc2 = crossword:aead_encrypt(K,I,{Plain,Assoc}), % determinism
	    Dec = crossword:aead_decrypt(K,Enc),
	    Enc2 =:= Enc andalso
	      {Plain, Assoc} =:= Dec
	  end).

prop_aead_server() ->
  ?FORALL({Algo, Plain, Assoc},
	  {aead_algo(), binary(), binary()},
	  begin
	    Ps = {Plain,Assoc},
	    K = crossword:aead_key(Algo),
	    I = crossword:aead_iv(Algo),
	    {ok,P} = crossword_aead_server:start_link(K),
	    E1 = crossword:aead_encrypt(K,I,Ps),
	    E2 = crossword_aead_server:encrypt(P,I,Ps),
	    D = crossword_aead_server:decrypt(P,E1),
	    E1 =:= E2 andalso D =:= Ps
	  end).
