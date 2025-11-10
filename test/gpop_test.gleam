import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode.{type Decoder}
import gleam/http
import gleam/http/request as http_request
import gleam/json
import gleam/option.{type Option}
import gleam/string
import gleeunit
import gpop

type HeaderInfo {
  HeaderInfo(typ: String, alg: String, jwk: Jwk)
}

type Jwk {
  Jwk(kty: String, crv: String, x: String, y: String)
}

type PayloadInfo {
  PayloadInfo(
    htm: String,
    htu: String,
    nonce: Option(String),
    ath: Option(String),
    iat: Int,
  )
}

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn dpop_proof_encodes_request_test() {
  let key = gpop.generate_key()
  let request =
    http_request.new()
    |> http_request.set_method(http.Post)
    |> http_request.set_host("server.test")
    |> http_request.set_path("/token")

  let updated = gpop.with_proof(request, key, option.None)
  let assert Ok(proof) = http_request.get_header(updated, "dpop")
  let assert [header_segment, payload_segment, _] = string.split(proof, ".")
  let header = parse_segment(header_segment, header_decoder())
  let payload = parse_segment(payload_segment, payload_decoder())

  assert header.typ == "dpop+jwt"
  assert header.alg == "ES256"
  assert header.jwk.kty == "EC"
  assert header.jwk.crv == "P-256"
  assert payload.htm == "POST"
  assert payload.htu == "https://server.test/token"
  assert payload.nonce == option.None
  assert payload.ath == option.None
  assert payload.iat > 0
}

pub fn authorization_header_includes_ath_test() {
  let key = gpop.generate_key()
  let token = "opaque-token"
  let request =
    http_request.new()
    |> http_request.set_method(http.Get)
    |> http_request.set_scheme(http.Http)
    |> http_request.set_host("api.service")
    |> http_request.set_port(8080)
    |> http_request.set_path("/resource")

  let updated =
    gpop.with_authorization(request, key, token, option.Some("fresh-nonce"))

  let assert Ok(auth_header) = http_request.get_header(updated, "authorization")
  assert auth_header == "DPoP opaque-token"

  let assert Ok(proof) = http_request.get_header(updated, "dpop")
  let assert [_, payload_segment, _] = string.split(proof, ".")
  let payload = parse_segment(payload_segment, payload_decoder())
  let expected_ath =
    crypto.hash(crypto.Sha256, <<token:utf8>>)
    |> bit_array.base64_url_encode(False)

  assert payload.ath == option.Some(expected_ath)
  assert payload.nonce == option.Some("fresh-nonce")
  assert payload.htm == "GET"
  assert payload.htu == "http://api.service:8080/resource"
}

fn parse_segment(segment: String, decoder: Decoder(a)) -> a {
  let assert Ok(bits) = bit_array.base64_url_decode(segment)
  let assert Ok(text) = bit_array.to_string(bits)
  let assert Ok(value) = json.parse(text, decoder)
  value
}

fn header_decoder() -> Decoder(HeaderInfo) {
  use typ <- decode.field("typ", decode.string)
  use alg <- decode.field("alg", decode.string)
  use jwk <- decode.field("jwk", jwk_decoder())
  decode.success(HeaderInfo(typ:, alg:, jwk: jwk))
}

fn jwk_decoder() -> Decoder(Jwk) {
  use kty <- decode.field("kty", decode.string)
  use crv <- decode.field("crv", decode.string)
  use x <- decode.field("x", decode.string)
  use y <- decode.field("y", decode.string)
  decode.success(Jwk(kty:, crv:, x:, y:))
}

fn payload_decoder() -> Decoder(PayloadInfo) {
  use htm <- decode.field("htm", decode.string)
  use htu <- decode.field("htu", decode.string)
  use nonce <- decode.optional_field(
    "nonce",
    option.None,
    decode.optional(decode.string),
  )
  use ath <- decode.optional_field(
    "ath",
    option.None,
    decode.optional(decode.string),
  )
  use iat <- decode.field("iat", decode.int)
  decode.success(PayloadInfo(htm:, htu:, nonce:, ath:, iat:))
}
