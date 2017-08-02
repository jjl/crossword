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
  {ok, Ref} = gen_server:call(Name, {encrypt,Plain}),
  receive
    {Ref,Ret} -> Ret
  end.

-spec encrypt(term(), binary(), aead_plain()) -> aead_cipher().
encrypt(Name, IV, Plain) ->
  {ok,Ref} = gen_server:call(Name,{encrypt, IV, Plain}),
  receive
    {Ref,Ret} -> Ret
  end.

-spec decrypt(term(), aead_cipher()) -> aead_plain().
decrypt(Name, Cipher) ->
  {ok, Ref} = gen_server:call(Name, {decrypt,Cipher}),
  receive
    {Ref,Ret} -> Ret
  end.

%%% Link api

-spec start_link(aead_key()) -> term().
start_link(Key) ->
  gen_server:start_link(?MODULE, Key, []).
-spec start_link(aead_key(), term()) -> _.
start_link(Key, Name) ->
  gen_server:start_link(Name, ?MODULE, Key, []).

%%% Implementation

-spec handle_encrypt(pid(), aead_key(), aead_plain()) -> aead_encrypt_result().
handle_encrypt({From, _}, Key, Plain) ->
  Ref = make_ref(),
  spawn(fun () ->
	    Ret = crossword:aead_encrypt(Key, Plain),
	    From ! {Ref,Ret}
	end),
  {reply, {ok, Ref}, Key}.

-spec handle_encrypt(pid(), aead_key(), aead_iv(), aead_plain()) -> aead_encrypt_result().
handle_encrypt({From, _},Key, IV, Plain) ->
  Ref = make_ref(),
  spawn(fun () ->
	    R = crossword:aead_encrypt(Key, IV, Plain),
	    From ! {Ref,R}
	end),
  {reply, {ok, Ref}, Key}.

-spec handle_decrypt(pid(), aead_key(), aead_cipher()) -> aead_decrypt_result().
handle_decrypt({From,_}, Key, Cipher) ->
  Ref = make_ref(),
  spawn(fun () ->
	    R = crossword:aead_decrypt(Key, Cipher),
	    From ! {Ref, R}
	end),
  {reply, {ok, Ref}, Key}.

%%% gen_server callbacks

init(Key) ->
  true = crossword:aead_key_valid(Key),
  {ok, Key}.

handle_call(Msg, From, Key) ->
  case Msg of
    {encrypt, Plain} -> handle_encrypt(From, Key, Plain);
    {encrypt, IV, Plain} -> handle_encrypt(From, Key, IV, Plain);
    {decrypt, Cipher} -> handle_decrypt(From, Key, Cipher);
    _ -> {reply,{error, unknown_action, Msg},Key}
  end.
      
handle_cast(_Msg, Key) ->
  {noreply,Key}.  
