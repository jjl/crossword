The irresponsible software guild presents...

# crossword

Cryptography for the clueless

## Usage

```erlang
(james@sputnik)1> K = crossword:aead_key(aes_gcm).
{aes_gcm,<<212,98,126,100,78,34,117,79,252,14,173,32,175,115,176,153>>}
(james@sputnik)2> C = crossword:aead_encrypt(K,{<<"hello">>,<<"world">>}).
{aes_gcm,<<237,135,7,171,170,58,158,81,48,55,228,240,167,239,6,64>>,
         <<"world">>,<<"~v]òÕ">>,
         <<248,131,185,62,18,58,90,244,185,242,249,185,241,249,113,198>>}
(james@sputnik)3> crossword:aead_decrypt(K,C).
{<<"hello">>,<<"world">>}
(james@sputnik)4> K2 = crossword:aead_key(chacha20_poly1305).
{chacha20_poly1305,<<122,176,212,35,23,57,163,149,113,77,
                     191,61,79,63,173,195,223,29,63,88,0,
                     108,142,34,61,232,168,...>>}
(james@sputnik)5> C2 = crossword:aead_encrypt(K2,{<<"hello">>,<<"world">>}).
{chacha20_poly1305,<<129,131,193,1,157,93,243,73,219,164,241,230,68,117,121,25>>,
                   <<"world">>,<<112,93,76,161,153>>,
                   <<12,100,106,113,73,53,21,177,91,163,165,202,59,150,20,112>>}
(james@sputnik)6> crossword:aead_decrypt(K2,C2).
{<<"hello">>,<<"world">>}
```

## API

### Module: `crossword`

Cryptographic functions wrapped for ease-of-use

#### aead api

| Feature      | Description                             |
| Key Model    | Secret                                  |
| Tamperproof? | Yes                                     |
| Bonus        | Also authenticates extra plaintext data |

Types:

```erlang
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
-type length_result() :: integer() | error.
```

Functions:

* `crossword:aead_key(Algo) -> Key`
  Algo: `aead_algo()`, 
  Example: `crossword:aead_key(aes_gcm)`
  Returns: `aead_key()`
* `crossword:aead_iv(Algo)  -> IV`
  Algo: `aead_algo()`, 
  Example: `crossword:aead_iv(aes_gcm)`
  Returns: `aead_iv()`
* `crossword:aead_encrypt(Key,{Msg,Extra}) -> aead_encrypt_result()`
  Key: `aead_key()`, as gotten from `aead_key/1`
  Msg: `binary()`, message you want to encrypt
  Extra: `binary()`, extra data to authenticate (but not encrypt)
  Returns: `aead_encrypt_result()`
  Example: `crossword:aead_encrypt(aead_key(aes_gcm), {<<"hello">>,<<"world">>})`
* `crossword:aead_encrypt(Key, IV, {Msg, Extra}) -> aead_encrypt_result()`
  Key: `aead_key()`, as gotten from `aead_key/1`
  IV: `aead_iv()`, as gotten from `aead_iv/1`
  Msg: `binary()`, message you want to encrypt
  Extra: binary(), extra data to authenticate (but not encrypt)
  Returns: `aead_encrypt_result()`
  Example: `crossword:aead_encrypt(aead_key(aes_gcm), aead_iv(aes_gcm), {<<"hello">>,<<"world">>})`
* `crossword:aead_decrypt(Key, Cipher) -> aead_decrypt_result()`
  Key: `aead_key()`, as gotten from `aead_key/1`
  Cipher: `aead_cipher()`, as gotten from `aead_encrypt/2`, `aead_encrypt/3`
  Returns: `aead_decrypt_result()`
  Example: `crossword:aead_decrypt(Key, Encrypted)`
* `crossword:aead_valid(Key) -> boolean()`
  Key: `aead_key()`, as gotten from `aead_key/1`
  Example: `crossword:aead_valid(aead_key(aes_gcm))`
  Returns: `boolean()`
* `crossword:aead_iv_length(Algo :: aead_algo())`
  Algo: `aead_algo()`
  Returns: `length_result()`
  Example: `crossword:aead_iv_length(aes_gcm)`
* `crossword:aead_key_length(Algo :: aead_algo())`
  Algo: `aead_algo()` 
  Example: `crossword:aead_key_length(aes_gcm)`
  Returns: `length_result()`

### Module: `crossword_aead_server`

A simple server that remembers an aead key for encryption/decryption tasks

## Cryptographic notes

### Algorithm details

| Kind | Algorithm           | Key Size (bits) | IV Size | Notes                                           |
|------|---------------------|-----------------|---------|-------------------------------------------------|
| aead | `aes_gcm`           | 128             | 128     | Very fast when hardware support is available    |
| aead | `chacha20_poly1305` | 256             | 128     | Faster without hardware assist, better security |

### Post-Quantum Security

There are no sufficiently advanced general purpose quantum computers yet, however, it's useful to plan for their potential existence.

| Algorithm           | Break     | Effect                               |
| `aes_gcm`           | Destroyed | Past messages become readable        |
| `chacha20_poly1305` | MAC only  | Future messages may be tampered with |

## Copyright and License

crossword is (c) 2017 James Laver

MIT LICENSE

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
