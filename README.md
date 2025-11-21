# gpop

[![Package Version](https://img.shields.io/hexpm/v/gpop)](https://hex.pm/packages/gpop)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/gpop/)
[![GitHub License](https://img.shields.io/github/license/edgerunner/gpop)](https://github.com/edgerunner/gpop/blob/development/LICENSE)
![Platform: Erlang](https://img.shields.io/badge/platform-erlang-orange?label=platform&color=orange)



gpop is a tiny Gleam helper for producing [DPoP proofs](https://datatracker.ietf.org/doc/html/rfc9449)
with `gleam_http` requests. It uses Erlang's `public_key` module under the hood to
generate and sign ES256 keys, so you can bind proofs to requests and bearer
tokens without leaving Gleam.

```sh
gleam add gpop@1
```

```gleam
import gleam/http
import gleam/http/request
import gleam/option
import gpop

pub fn main() {
  let key = gpop.generate_key()

  // When getting a new DPoP token
  request.new()
  |> request.set_method(http.Post)
  |> request.set_host("auth-server.example")
  |> request.set_path("/token")
  |> gpop.with_proof(key:, nonce: option.None)


  // Later, when using the obtained access token:
  request.new()
  |> request.set_method(http.Get)
  |> request.set_host("resource-server.example")
  |> request.set_path("/some-resource")
  |> gpop.with_authorization(key:, access_token, nonce: option.Some(nonce))
}
```

Further documentation can be found at <https://hexdocs.pm/gpop>.

## Development

```sh
gleam test  # Run the tests
```
### The future
- [ ] Support more signing algorithms (Please open an issue)
- [ ] Verify DPoP tokens
- [ ] Javascript platform support through the WebCrypto API
