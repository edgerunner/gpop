import gleam/bit_array
import gleam/crypto
import gleam/http
import gleam/http/request.{type Request}
import gleam/json.{type Json}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/pair
import gleam/time/timestamp
import gleam/uri.{Uri}
import youid/uuid

/// An ES256 key pair suitable for DPoP proofs
pub opaque type Key {
  Key(pair: P256Keypair, x: BitArray, y: BitArray)
}

/// Generate a new ES256 key pair suitable for DPoP proofs.
pub fn generate_key() -> Key {
  let #(pair, public_key) = generate_p256_keypair()
  let assert <<4, x:bits-size(256), y:bits-size(256)>> = public_key
  Key(pair:, x:, y:)
}

/// Attach a standalone DPoP proof header to the request.
pub fn with_proof(
  request req: Request(body),
  key key: Key,
  nonce nonce: Option(String),
) -> Request(body) {
  let proof = build_proof(req, key, nonce, None)
  request.set_header(req, "dpop", proof)
}

/// Attach an Authorization header using the DPoP scheme together with the
/// accompanying proof bound to the access token.
pub fn with_authorization(
  request req: Request(body),
  key key: Key,
  access_token access_token: String,
  nonce nonce: Option(String),
) -> Request(body) {
  let proof =
    build_proof(req, key, nonce, Some(hash_access_token(access_token)))

  req
  |> request.set_header("authorization", "DPoP " <> access_token)
  |> request.set_header("dpop", proof)
}

fn build_proof(
  request: Request(body),
  key: Key,
  nonce: Option(String),
  ath: Option(String),
) -> String {
  let header = header_json(key)
  let payload = payload_json(request, nonce, ath)
  sign_jwt(header, payload, key)
}

fn header_json(key: Key) -> Json {
  json.object([
    #("typ", json.string("dpop+jwt")),
    #("alg", json.string("ES256")),
    #("jwk", jwk_json(key)),
  ])
}

fn jwk_json(key: Key) -> Json {
  json.object([
    #("kty", json.string("EC")),
    #("crv", json.string("P-256")),
    #("x", json.string(encode_coordinate(key.x))),
    #("y", json.string(encode_coordinate(key.y))),
  ])
}

fn payload_json(
  request: Request(body),
  nonce: Option(String),
  ath: Option(String),
) -> Json {
  let htm = http.method_to_string(request.method)
  let htu = Uri(..request.to_uri(request), query: None, fragment: None)
  let claims =
    [
      #("htm", json.string(htm)),
      #("htu", json.string(uri.to_string(htu))),
      #("jti", json.string(uuid.v4_string())),
      #("iat", json.int(current_epoch_seconds())),
    ]
    |> append_optional_string("nonce", nonce)
    |> append_optional_string("ath", ath)

  json.object(claims)
}

fn append_optional_string(
  claims: List(#(String, Json)),
  name: String,
  value: Option(String),
) -> List(#(String, Json)) {
  case value {
    None -> claims
    Some(v) -> list.flatten([claims, [#(name, json.string(v))]])
  }
}

fn sign_jwt(header: Json, payload: Json, key: Key) -> String {
  let header_segment = header |> json.to_string |> encode_segment
  let payload_segment = payload |> json.to_string |> encode_segment
  let signing_input = header_segment <> "." <> payload_segment
  let signature =
    <<signing_input:utf8>>
    |> sign_es256(key.pair)
    |> bit_array.base64_url_encode(False)

  signing_input <> "." <> signature
}

fn encode_segment(value: String) -> String {
  bit_array.base64_url_encode(<<value:utf8>>, False)
}

fn encode_coordinate(coordinate: BitArray) -> String {
  bit_array.base64_url_encode(coordinate, False)
}

fn hash_access_token(access_token: String) -> String {
  crypto.hash(crypto.Sha256, <<access_token:utf8>>)
  |> bit_array.base64_url_encode(False)
}

fn current_epoch_seconds() -> Int {
  timestamp.system_time()
  |> timestamp.to_unix_seconds_and_nanoseconds
  |> pair.first
}

type P256Keypair

@external(erlang, "gpop_ffi", "generate_p256_keypair")
fn generate_p256_keypair() -> #(P256Keypair, BitArray)

@external(erlang, "gpop_ffi", "sign_es256")
fn sign_es256(message: BitArray, key: P256Keypair) -> BitArray
