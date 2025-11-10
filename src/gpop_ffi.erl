-module(gpop_ffi).

-export([generate_p256_keypair/0, sign_es256/2]).

-include_lib("public_key/include/public_key.hrl").

generate_p256_keypair() ->
    Key = public_key:generate_key({namedCurve, secp256r1}),
    #'ECPrivateKey'{publicKey = PublicKey} = Key,
    {Key, PublicKey}.

sign_es256(Message, Key) ->
    public_key:sign(Message, sha256, Key).
