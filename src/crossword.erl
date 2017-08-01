-module(crossword).

-export([aead_key/1, aead_iv/1, aead_encrypt/2, aead_encrypt/3, aead_decrypt/2]).
-export([aead_key_length/1, aead_iv_length/1, aead_key_valid/1, aead_iv_valid/1]).
-include("../include/crossword.hrl").

%% -export([sym_enc_key/1, sym_enc_iv/1, sym_enc_key_length/1, sym_enc_key_valid/1]).
%% -export([sym_auth_key_length/1, sym_auth_key/1, sym_auth_key_valid/1, sym_auth/2, sym_auth_verify/2]).

%%% AEAD Encryption API

-spec aead_key(Algo :: aead_algo()) -> aead_key().
aead_key(Algo) ->
  case aead_key_length(Algo) of
    error -> error;
    Len -> {Algo,crypto:strong_rand_bytes(Len)}
  end.

-spec aead_key_valid(Key :: aead_key()) -> boolean().
aead_key_valid({Algo, Key}) ->
  aead_key_length(Algo) =:= byte_size(Key);
aead_key_valid(_) -> false.

-spec aead_iv(Algo :: aead_algo()) -> aead_iv().
aead_iv(Algo) -> 
  case aead_iv_length(Algo) of
    error -> error;
    Len -> {Algo, crypto:strong_rand_bytes(Len)}
  end.

aead_iv_valid({Algo, IV}) ->
  aead_iv_length(Algo) =:= byte_size(IV);
aead_iv_valid(_) -> false.


-spec aead_encrypt(Key :: aead_key(), Plaintexts :: aead_plain()) -> aead_cipher().
aead_encrypt(Key={Algo,_}, Plain) ->
  case aead_iv(Algo) of
    {_, IV} -> aead_encrypt(Key, IV, Plain);
    _ -> error
  end;
aead_encrypt(_,_) -> error.

-spec aead_encrypt(Key :: aead_key(), IV :: aead_iv(), Plaintexts :: aead_plain()) -> aead_cipher().
aead_encrypt(K={Algo,Key}, I={Algo, IV}, {Plaintext, Assoc}) ->
  case {aead_key_valid(K),aead_iv_valid(I)} of
    {true, true} -> case crypto:block_encrypt(Algo, Key, IV, {Assoc,Plaintext}) of
		      error -> error;
		      {Ciphertext, Ciphertag} -> {Algo, Assoc, IV, Ciphertext, Ciphertag}
		    end;
    _ -> error
  end;
aead_encrypt(_,_,_) ->
  error.

-spec aead_decrypt(binary(), aead_cipher()) -> result().
aead_decrypt({Algo,Key}, {Algo, Assoc, IV, Ciphertext, Ciphertag}) ->
  case crypto:block_decrypt(Algo, Key, IV, {Assoc, Ciphertext, Ciphertag}) of
    error -> error;
    V -> {V, Assoc}
  end;
aead_decrypt(_,_) -> error.

%% -type enc_data() :: {sym_enc_algo(), binary()}.
%% -type authed_data() :: {sym_auth_algo(), binary(), binary()}.

%% -type sym_enc_algo() :: aes_ctr.
%% -type sym_auth_algo() :: hmac_sha256 | poly1305.

%% -type sym_enc_key() :: {sym_enc_algo(), binary()}.
%% -type sym_auth_key() :: {sym_auth_algo(), binary()}.

%%% Symmetric Encryption and Authentication

%% sym_encrypt_auth(EKey, IV, AKey, Plaintext) -> ok.
%% sym_decrypt_verify(EKey, IV, AKey, Ciphertext) -> ok.

%%% Symmetric Encryption

%% -spec sym_enc_key_valid(sym_enc_key()) -> boolean().
%% sym_enc_key_valid({Algo,Key}) ->
%%   sym_enc_key_length(Algo) =:= byte_size(Key).


%% sym_enc_key(Algo) ->
%%   {Algo, sym_enc_key_length(Algo)}.
%% sym_enc_iv(Algo) -> error.

%% -spec sym_encrypt(sym_enc_key(), binary(), binary()) -> result().
%% sym_encrypt(K={Algo,Key}, IV, Plaintext) ->
%%   case Algo of
%%     aes_ctr256 -> stream_encrypt(aes_
%%        c

%% -spec sym_decrypt(sym_enc_key(), binary(), binary()) -> result().
%% sym_decrypt(Key, IV, Ciphertext) -> ok.

%%% Symmetric Authentication

%% -spec sym_auth_key_valid(sym_auth_key()) -> boolean().
%% sym_auth_key_valid({Algo,Key}) ->
%%   sym_auth_key_length(Algo) =:= byte_size(Key).

%% -spec sym_auth(sym_auth_key(), binary()) -> authed_data().
%% sym_auth(K={Algo,Key},Data) ->
%%   true = sym_auth_key_valid(K),
%%   {Algo, Data,
%%    case Algo of
%%      hmac_sha256 -> crypto:hmac(sha256,Key,Data)
%%    end}.

%% -spec sym_auth_verify(sym_auth_key(), authed_data()) -> boolean().
%% sym_auth_verify(K={Algo,_},{Algo2,Data,Mac}) when Algo =:= Algo2 ->
%%   Mac2 = sym_auth(K, Data),
%%   Mac =:= Mac2.

%%% internals

-spec aead_key_length(aead_algo()) -> integer().
aead_key_length(aes_gcm) -> 16;
aead_key_length(chacha20_poly1305) -> 32;
aead_key_length(_) -> error.
  
-spec aead_iv_length(aead_algo()) -> integer().
aead_iv_length(aes_gcm) -> 16;
aead_iv_length(chacha20_poly1305) -> 16;
aead_iv_length(_) -> error.

%% -spec sym_enc_key_length(sym_enc_algo()) -> integer().
%% sym_enc_key_length(aes_ctr) -> 32.

%% -spec sym_env_iv_length(sym_enc_algo()) -> integer().
%% sym_enc_iv_length(aes_ctr) -> 16.

%% -spec sym_auth_key_length(sym_auth_algo()) -> integer().
%% sym_auth_key_length(hmac_sha256) -> 32.
%% % sym_auth_key_length(poly1305) -> 16.

%% -spec sym_auth_key(sym_auth_algo()) -> sym_auth_key().
%% sym_auth_key(Algo) ->
%%   Len = sym_auth_key_length(Algo),
%%   {Algo,crypto:secure_rand_bytes(Len)}.
