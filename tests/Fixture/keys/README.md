# Test keys

Two key pairs for the tests of this package and nothing else: an identity provider pair and a service provider pair
(section 9.1 of `spec/model.md`). The private keys are public by construction, in this repository, and sign no real
document anywhere. Never trust either certificate outside the tests.

Each is an RSA-2048 key with a self-signed certificate valid ten years from its generation, PEM, made in Alpine 3.22.6
with OpenSSL 3.5.9 on 30 September 2026, from the directory of this file:

```
docker run --rm -v "$PWD:/keys" -w /keys alpine:3.22 sh -c 'apk add -q openssl \
    && openssl req -x509 -newkey rsa:2048 -nodes -keyout idp-signing-key.pem -out idp-signing-certificate.pem \
        -days 3650 -subj "/CN=saml2-model test identity provider key, not a secret" \
    && openssl req -x509 -newkey rsa:2048 -nodes -keyout sp-signing-key.pem -out sp-signing-certificate.pem \
        -days 3650 -subj "/CN=saml2-model test service provider key, not a secret"'
```

| File | Serves | Valid | SHA-256 fingerprint of the certificate |
|---|---|---|---|
| `idp-signing-key.pem`, `idp-signing-certificate.pem` | the identity provider: it signs responses, assertions, logout messages and its metadata; its certificate is the one the identity provider's metadata carries | 30 September 2026 to 27 September 2036 | `30:D1:2B:B2:5C:D7:74:63:30:E8:5A:A7:31:61:A5:02:1C:8B:0E:27:98:AD:B4:23:31:60:87:F1:90:C4:72:7B` |
| `sp-signing-key.pem`, `sp-signing-certificate.pem` | the service provider: it signs authentication requests, logout messages and its metadata; its certificate is the one the service provider's metadata carries | 30 September 2026 to 27 September 2036 | `52:48:FA:3C:DE:44:AE:D4:72:53:D8:D5:FB:1C:08:CE:7D:ED:0B:FF:57:26:34:3C:81:11:9C:12:B6:1A:1D:30` |

The SimpleSAMLphp library of `tests/Interop/simplesamlphp/library/` signs its fixtures with these two pairs. The
SimpleSAMLphp installation of `tests/Interop/simplesamlphp/installation/` has pairs of its own, next to it.
