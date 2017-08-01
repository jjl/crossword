-module(crossword_aead_server).
-behaviour(gen_server).
% Crypto API
-export([encrypt/2, encrypt/3, decrypt/2]).
% Link API
-export([start_link/1, start_link/2]).
% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2]).

-include("../include/crossword.hrl").

%%% Crypto API

-spec encrypt(term(), aead_plain()) -> aead_cipher().
encrypt(Name, Plain) ->
  gen_server:call(Name, {encrypt,Plain}).

-spec encrypt(term(), binary(), aead_plain()) -> aead_cipher().
encrypt(Name, IV, Plain) ->
  gen_server:call(Name,{encrypt, IV, Plain}).

-spec decrypt(term(), aead_cipher()) -> aead_plain().
decrypt(Name, Cipher) ->
  gen_server:call(Name, {decrypt,Cipher}).

%%% Link api

-spec start_link(aead_key()) -> term().
start_link(Key) ->
  gen_server:start_link(?MODULE, Key, []).
-spec start_link(aead_key(), term()) -> _.
start_link(Key, Name) ->
  gen_server:start_link(Name, ?MODULE, Key, []).

%%% Implementation

-spec handle_encrypt(pid(), aead_key(), aead_plain()) -> aead_encrypt_result().
handle_encrypt(From, Key, Plain) ->
  spawn(fun () -> From ! crossword:aead_encrypt(Key, Plain) end).

-spec handle_encrypt(pid(), aead_key(), aead_iv(), aead_plain()) -> aead_encrypt_result().
handle_encrypt(From, Key, IV, Plain) ->
  spawn(fun () -> From ! crossword:aead_encrypt(Key, IV, Plain)	end).

-spec handle_decrypt(pid(), aead_key(), aead_cipher()) -> aead_decrypt_result().
handle_decrypt(From, Key, Cipher) ->
  spawn(fun () -> From ! crossword:aead_encrypt(Key, Cipher) end).

%%% gen_server callbacks

init(Key) ->
  true = crossword:aead_key_valid(Key),
  {ok, Key}.

handle_call(Msg, From, Key) ->
  case Msg of
    {encrypt, Plain} -> handle_encrypt(From, Key, Plain),
			{noreply,Key};
    {encrypt, IV, Plain} -> handle_encrypt(From, Key, IV, Plain),
			    {noreply,Key};
    {decrypt, Cipher} -> handle_decrypt(From, Key, Cipher),
			 {noreply,Key};
    _ -> {reply,{error, unknown_action, Msg},Key}
  end.
      
handle_cast(_Msg, Key) ->
  {noreply,Key}.  
