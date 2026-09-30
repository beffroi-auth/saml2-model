# SimpleSAMLphp, both ways

The judge of sub-spike 9b for this package (section 9.5 of `spec/model.md`), in two halves, reproducible from a clean
checkout and never a dependency of the package: nothing here is in the root `composer.json`, and no CI job runs it
(section 12). Each half is run by hand, from the root of the repository, with Docker; what it produced is committed
under `tests/Fixture/real/` (section 9.4), named with its origin, its version and its date, bytes as written or as
decoded, disposable identities only.

| | |
|---|---|
| `library/` | a throwaway Composer project running `simplesamlphp/saml2`, SimpleSAMLphp's SAML 2 library, in a container: `produce.php` writes the fixtures with the test keys, `verify.php` validates what a producer wrote |
| `installation/` | SimpleSAMLphp installed as an identity provider and as a service provider in containers, and `capture.sh`, which plays a login and a logout with `curl` and keeps every SAML document |
| `xmlsec1-verify.sh` | verifies every XML signature of a batch with xmlsec1, the implementation independent of both SimpleSAMLphp and the model |

Phase 1 of story #11, on 30 September 2026, built what does not need the model's code: the test keys, the library
half, the installation half and the captures. Phase 2 posts the model's own documents into SimpleSAMLphp once the
writers exist (stories #9 and #10).

## Versions

| What | Version | Pinned by | Date |
|---|---|---|---|
| `simplesamlphp/saml2` | 4.20.3 | `library/composer.json` (exact) and `library/composer.lock` | released 29 May 2026, run 30 September 2026 |
| `robrichards/xmlseclibs`, under it | 3.1.5 | `library/composer.lock` | run 30 September 2026 |
| PHP of the library half | 8.4.25 | `ghcr.io/spomky-labs/phpqa:8.4`, Composer 2.10.3 | 30 September 2026 |
| SimpleSAMLphp | 2.5.3.1, slim release archive | `installation/Dockerfile`: the version, and the SHA-256 of the archive, `38d81fc60f358b46a58df38617b02f97f57793dcbf8e491c1abcedb6706ffe3c`, the one its release notes publish, checked by `sha256sum -c` at build | released 9 August 2026, captured 30 September 2026 |
| PHP and Apache of the installation | PHP 8.4.26, Apache 2.4.68, Debian 13.7 | `php:8.4.26-apache@sha256:75325cceea4f9a8200f4e9e146e8155ec1b6466b2957b87accf0286b94547cbd` | 30 September 2026 |
| Docker, Compose, curl of the capture | Docker 29.8.1, Compose 5.5.1, curl 8.7.1 (macOS) | the machine that ran it | 30 September 2026 |
| xmlsec1 | 1.3.7 (OpenSSL) | `apk add xmlsec` in `alpine:3.22` (3.22.6) | 30 September 2026 |

## 1. The library

### Which library

SimpleSAMLphp 2.5.3.1, the latest stable release on 30 September 2026 (section 2), ships two SAML libraries in its
`vendor/`: `simplesamlphp/saml2` 6.2.4 (namespace `SimpleSAML\SAML2\`) and `simplesamlphp/saml2-legacy` 4.20.3
(namespace `SAML2\`). Everything that signs, verifies, reads and writes a SAML message in the installation goes
through the second: `modules/saml/src/IdP/SAML2.php`, `modules/saml/src/Message.php` and the service provider's
controllers import `SAML2\Assertion`, `SAML2\Response`, `SAML2\AuthnRequest`, `SAML2\LogoutRequest`,
`SAML2\LogoutResponse` and `RobRichards\XMLSecLibs\XMLSecurityKey`; the 6.x library is imported only for its
constants, an enumeration and exception classes. `saml2-legacy` 4.20.3 is `simplesamlphp/saml2` 4.20.3 under
another package name: `diff -r` of the two `src/` trees differs by one unused `use` line in `SOAPClient.php`, and
`xmlseclibs` 3.1.5 is the same in both. The library half therefore pins `simplesamlphp/saml2` 4.20.3, the code the
installation runs, and the version `xml-security` ran for its own judge (its `tests/Dsig/Fixture/real/README.md`).
The 6.x library, on `simplesamlphp/xml-security` rather than `xmlseclibs`, is not exercised here.

### Commands

```
# Install the throwaway project (vendor/ is ignored, composer.lock is committed)
docker run --rm -v "$PWD/tests/Interop/simplesamlphp/library:/app" -w /app ghcr.io/spomky-labs/phpqa:8.4 \
    composer install -n --no-progress

# Write the fixtures into tests/Fixture/real/
docker run --rm -v "$PWD/tests/Interop/simplesamlphp/library:/app" -v "$PWD/tests/Fixture/keys:/keys:ro" \
    -v "$PWD/tests/Fixture/real:/out" -w /app ghcr.io/spomky-labs/phpqa:8.4 php produce.php

# Validate them with the library: every line OK, exit status 0
docker run --rm -v "$PWD/tests/Interop/simplesamlphp/library:/app" -v "$PWD/tests/Fixture/keys:/keys:ro" \
    -v "$PWD/tests/Fixture/real:/in:ro" -w /app ghcr.io/spomky-labs/phpqa:8.4 \
    php verify.php /in 'simplesamlphp-saml2-4.20.3-*.xml'

# A tampered copy must fail: one attribute value of the signed assertion changed, exit status 1
docker run --rm -v "$PWD/tests/Interop/simplesamlphp/library:/app" -v "$PWD/tests/Fixture/keys:/keys:ro" \
    -v "$PWD/tests/Fixture/real:/in:ro" -w /app ghcr.io/spomky-labs/phpqa:8.4 sh -c '
    mkdir /tmp/tampered && cp /in/simplesamlphp-saml2-4.20.3-*.xml /tmp/tampered/ \
    && sed -i "s/>member</>faculty</" /tmp/tampered/simplesamlphp-saml2-4.20.3-response-signed-assertion-2026-09-30.xml \
    && php verify.php /tmp/tampered; test $? -eq 1'

# Verify every signature with xmlsec1, each under the certificate of its signer's metadata
docker run --rm -v "$PWD:/project:ro" -w /project alpine:3.22 sh -c 'apk add -q xmlsec libxml2-utils \
    && sh tests/Interop/simplesamlphp/xmlsec1-verify.sh tests/Fixture/real "simplesamlphp-saml2-4.20.3-*.xml"'
```

### `produce.php`

It builds one exchange with the library's objects and signs it with the test keys of `tests/Fixture/keys/`, the
identity provider's key for what the identity provider sends, the service provider's for what the service provider
sends, the certificate in `KeyInfo` as SimpleSAMLphp writes it. Every value is fixed, IDs and times included, and
RSA PKCS#1 v1.5 signs deterministically: a second run on 30 September 2026 rewrote the nine files byte for byte.
The documents hold together, so that the model's validators accept them with a clock frozen at
`2026-09-30T12:00:00Z`: the response answers the `AuthnRequest`, its `Destination` and bearer `Recipient` are the
assertion consumer service of the service provider's metadata, its `Audience` the service provider's entity ID, the
`LogoutResponse` answers the `LogoutRequest`. The windows are those SimpleSAMLphp's identity provider writes by
default (`buildAssertion()` of `modules/saml/src/IdP/SAML2.php`): `NotBefore` 30 s before the issue instant, 300 s
of `assertion.lifetime` for `NotOnOrAfter` and the bearer `NotOnOrAfter`, 8 h of `session.duration` from the
`AuthnInstant` for `SessionNotOnOrAfter`.

| File under `tests/Fixture/real/` | What | Signed by |
|---|---|---|
| `simplesamlphp-saml2-4.20.3-authnrequest-signed-2026-09-30.xml` | an `AuthnRequest` in its HTTP-POST form, enveloped signature | service provider |
| `simplesamlphp-saml2-4.20.3-response-signed-assertion-2026-09-30.xml` | a response with its signed assertion, the response unsigned | identity provider |
| `simplesamlphp-saml2-4.20.3-response-signed-both-2026-09-30.xml` | the same response signed over its signed assertion | identity provider, twice |
| `simplesamlphp-saml2-4.20.3-logoutrequest-signed-2026-09-30.xml` | a `LogoutRequest` started by the service provider | service provider |
| `simplesamlphp-saml2-4.20.3-logoutresponse-signed-2026-09-30.xml` | the identity provider's `LogoutResponse` to it | identity provider |
| `simplesamlphp-saml2-4.20.3-idp-metadata-2026-09-30.xml`, `...-idp-metadata-signed-...` | the identity provider's metadata, unsigned and signed, carrying `idp-signing-certificate.pem` | identity provider |
| `simplesamlphp-saml2-4.20.3-sp-metadata-2026-09-30.xml`, `...-sp-metadata-signed-...` | the service provider's metadata, unsigned and signed, carrying `sp-signing-certificate.pem`, `AuthnRequestsSigned="true"` | service provider |

### `verify.php`

`php verify.php <directory> [<glob>]` reads every document of the directory that matches the glob (`*.xml` by
default) with the library, as SimpleSAMLphp reads what a peer sends. The keys come from the metadata of the batch,
never from a message (M-3): every `md:EntityDescriptor` is read first, each of its certificates must be one of the
test certificates of `tests/Fixture/keys/`, and a signed one is verified under its own; each message is then
verified under the signing certificates of the metadata of its `Issuer`, an assertion under those of its own
`Issuer`. Every `ds:Signature` a message or an assertion carries as a direct child must validate through the
object's own `validate()`, the call SimpleSAMLphp makes (`Message::checkSign()`); a message without any signature
fails, metadata without one passes. It prints one line per file, `OK` or `FAIL` and why, and exits with 1 when a
file fails. Phase 2 runs it on the model's written documents, in a directory of their own.

On 30 September 2026, on the nine files above: nine `OK`, exit status 0, the doubly signed response with both
signatures valid. On the tampered copy (`member` changed to `faculty` in the signed assertion of the response):
`FAIL simplesamlphp-saml2-4.20.3-response-signed-assertion-2026-09-30.xml: the library refuses to read it: Reference
validation failed`, exit status 1. A copy whose `LogoutRequest` had its `SessionIndex` changed failed as well, with
`signature not valid: Reference validation failed`.

Two behaviours of the library shaped the script. The constructor of a message (`SAML2\Message`) and of metadata
(`SignedElementHelper`) swallows a signature that fails its digest and then answers `validate()` with `false`, the
answer it gives for an unsigned message, while the constructor of an assertion lets the failure through as an
exception; the script therefore decides from the tree whether a signature is present before handing the document
to the library, and treats `false` for a present signature as a failure, asking `Utils::validateElement()` for the
reason. And `xmlseclibs` removes the `ds:Signature` it checked from the tree it was given, so the reason is asked on
a copy loaded again.

## 2. The installation

### Which release

SimpleSAMLphp 2.5.3.1, a security release of 9 August 2026, is the highest stable version on 30 September 2026;
2.4.10, published later (30 August 2026), is on the 2.4 maintenance branch. The slim archive is enough: it ships
`vendor/` and the `exampleauth` module, so the image runs no Composer. One image serves both roles, from
`php:8.4.26-apache` pinned by digest; `compose.yaml` mounts the configuration, the metadata and the keys of each:

| Port | Role | Entity ID |
|---|---|---|
| `127.0.0.1:8081` | identity provider | `http://localhost:8081/simplesaml/module.php/saml/idp/metadata` |
| `127.0.0.1:8082` | service provider `default-sp` | `http://localhost:8082/simplesaml/module.php/saml/sp/metadata/default-sp` |

Port 8180 is left to the Keycloak of story #14. The containers never call each other: every message goes through
the browser, here `curl`, and each side knows the other through static metadata (`saml20-sp-remote.php`,
`saml20-idp-remote.php`), which mirrors what the other side's metadata URL publishes.

### Test material

Disposable, committed on purpose, trusted nowhere:

- `installation/cert/`: the installation's own pairs, RSA-2048, self-signed certificates valid ten years, made in
  Alpine 3.22 with OpenSSL 3.5.9 on 30 September 2026, from that directory:
  ```
  docker run --rm -v "$PWD:/cert" -w /cert alpine:3.22 sh -c 'apk add -q openssl \
      && openssl req -x509 -newkey rsa:2048 -nodes -keyout idp.pem -out idp.crt -days 3650 \
          -subj "/CN=saml2-model SimpleSAMLphp test identity provider, not a secret" \
      && openssl req -x509 -newkey rsa:2048 -nodes -keyout sp.pem -out sp.crt -days 3650 \
          -subj "/CN=saml2-model SimpleSAMLphp test service provider, not a secret" && chmod 644 *'
  ```
  SHA-256 fingerprints: `idp.crt` `E9:BF:B2:4F:F6:84:64:BF:EE:13:76:ED:E6:FF:0C:B1:DC:31:99:1B:C6:CA:B4:52:3B:3A:F2:04:2F:F7:DB:87`,
  `sp.crt` `4A:F2:FD:74:E3:1B:2D:89:3B:C9:02:10:40:A7:9A:E1:F4:01:A6:D8:52:8E:9D:BF:E1:3C:41:BD:21:50:D4:6D`.
- The test user `student`, password `studentpass`, attributes `uid` = `test` and `eduPersonAffiliation` =
  `member`, `student`: the example user of SimpleSAMLphp's own `authsources.php.dist`.
- The two `secretsalt` values, which SimpleSAMLphp only uses to derive identifiers of this installation.

### Settings

Each `config.php` and `authsources.php` of `installation/idp/config/` and `installation/sp/config/` loads the file
SimpleSAMLphp 2.5.3.1 distributes (`config/config.php.dist`, `config/authsources.php.dist`, kept in the image as
`config-dist/`) and overrides the settings below; everything else is the distributed default. The metadata files
hold only what the role needs.

| Where | Setting | Value | Why |
|---|---|---|---|
| both `config.php` | `secretsalt` | a test value | SimpleSAMLphp refuses to run with the distributed `defaultsecretsalt` (`Utils\Config::getSecretSalt()`) |
| both `config.php` | `logging.handler` | `errorlog` | no syslog in the container: the logs go to `docker compose logs` |
| identity provider `config.php` | `module.enable` | `exampleauth` added | the `exampleauth:UserPass` source of the test user |
| identity provider `config.php` | `enable.saml20-idp` | `true` | the identity provider role is off by default |
| identity provider `config.php` | `session.cookie.name`, `session.phpsession.cookiename`, `session.authtoken.cookiename` | `IdPSimpleSAMLSessionID`, `IdPSimpleSAML`, `IdPSimpleSAMLAuthToken` | both parties answer on `localhost`, and a browser, like the one cookie jar of `capture.sh`, sends the cookies of a host to all its ports: with the default names, each party would overwrite the other's session cookie |
| identity provider `authsources.php` | `example-userpass` | the distributed example, one user | the distributed file carries it commented out |
| `saml20-idp-hosted.php` | entity ID, `host`, `privatekey`, `certificate`, `auth` | its metadata URL, `__DEFAULT__`, `idp.pem`, `idp.crt`, `example-userpass` | what a hosted identity provider needs; no signing option is set, so `saml20.sign.assertion` and `saml20.sign.response` keep their default, `true`, and `sign.logout` stays unset |
| `saml20-sp-remote.php` | the service provider | its assertion consumer service (HTTP-POST), its single logout service (HTTP-Redirect), `sp.crt` | the identity provider verifies the service provider's signed requests under this certificate |
| service provider `authsources.php` | `default-sp` `entityID` | its metadata URL | SimpleSAMLphp refuses the distributed `https://myapp.example.org/` |
| service provider `authsources.php` | `default-sp` `idp` | the identity provider's entity ID | no discovery page |
| service provider `authsources.php` | `default-sp` `privatekey`, `certificate` | `sp.pem`, `sp.crt` | the service provider's own pair |
| service provider `authsources.php` | `default-sp` `sign.authnrequest`, `sign.logout` | `true`, `true` | the service provider signs its authentication and logout requests |
| `saml20-idp-remote.php` | the identity provider | its single sign-on and single logout services (HTTP-Redirect), `idp.crt` | the service provider verifies the response under this certificate |
| `saml20-idp-hosted.php`, second configuration only | `saml20.sign.response` | `false` when the container runs with `SSP_SIGN_RESPONSE=false` | the second capture, where the assertion alone is signed |

SimpleSAMLphp 2.5.3.1 signs the response as well as the assertion by default: `saml20.sign.response` defaults to
`true` (`docs/simplesamlphp-reference-idp-hosted.md`, and `buildResponse()` of `modules/saml/src/IdP/SAML2.php`:
`getOptionalBoolean('saml20.sign.response', true)`). The default configuration therefore gives the doubly signed
response, and the second configuration turns the response's signature off to give the response whose assertion
alone is signed, the reverse of what section 9.4 of the specification supposes ("a response signed over it where
the installation is configured to").

### Commands

```
# Build, start, play the login and the logout in both configurations, keep the documents in tests/Fixture/real/
bash tests/Interop/simplesamlphp/installation/capture.sh

# Stop
docker compose -f tests/Interop/simplesamlphp/installation/compose.yaml down
```

`capture.sh` needs Docker, bash and curl on the machine, and nothing else: it decodes and verifies with PHP inside
the running identity provider container. With one cookie jar and one hop at a time, never following a redirect
blindly:

1. `docker compose up -d --build --force-recreate`, the default configuration; both metadata fetched from
   `http://localhost:8081/simplesaml/module.php/saml/idp/metadata` and
   `http://localhost:8082/simplesaml/module.php/saml/sp/metadata/default-sp`, kept as served.
2. `GET` the service provider's `module.php/saml/sp/login/default-sp?ReturnTo=...`: a redirect to the identity
   provider's single sign-on service carrying `SAMLRequest`, `SigAlg` and `Signature`. The `AuthnRequest` is
   URL-decoded, base64-decoded and raw-inflated (`gzinflate()`), and the signature over the query string, the octets
   `SAMLRequest=...&SigAlg=...` as they appear in the URL (SAML Bindings section 3.4.4.1), is verified with
   `openssl_verify()` under the certificate of the service provider's metadata kept at step 1.
3. `GET` that URL, then the login form it redirects to; `POST` the test user's credentials with the form's
   `AuthState`; follow the redirects on the identity provider's side to the page that holds the HTTP-POST form. Its
   `SAMLResponse` field is base64-decoded and kept.
4. `POST` `SAMLResponse` and `RelayState` to the service provider's assertion consumer service, which must answer
   with a redirect to the `ReturnTo` of step 2: it accepted the response and opened its session.
5. `GET` the service provider's `module.php/core/logout/default-sp?ReturnTo=...`: a redirect to the identity
   provider's single logout service carrying the `LogoutRequest`, decoded and verified as at step 2.
6. `GET` it, and follow the identity provider's redirects (`module.php/core/logout-resume`) to the redirect to the
   service provider's single logout service carrying the `LogoutResponse`, decoded as at step 2, its query string
   signature verified when there is one; `GET` it, and the service provider redirects to its `ReturnTo`.
7. A probe, with a new cookie jar: steps 2 and 3 again, then the response's own `IssueInstant` moved by one second,
   outside the assertion, so that the response's signature fails its digest while the assertion's holds, posted to
   the assertion consumer service; the script prints what the service provider did of it and keeps nothing
   (finding F-3).
8. The identity provider recreated with `SSP_SIGN_RESPONSE=false`, a new cookie jar, steps 2 to 4 again: the
   response is kept; the `AuthnRequest` of that second login is not.
9. The identity provider recreated in the default configuration, left running.

### Captures

On 30 September 2026, between 10:34:38 and 10:34:41 UTC, from a clean image (`docker compose down --rmi local`,
`docker builder prune` first), `capture.sh` ran through; every step above answered as expected, the service
provider accepted both responses, and the probe printed `probe: the service provider ACCEPTED a response whose own
signature fails, its assertion's holding`. The half took about three quarters of an hour of the three hours it was
given. A second run rewrites both metadata byte for byte; the messages differ by their IDs and times.

| File under `tests/Fixture/real/` | What | Carried by | Signed |
|---|---|---|---|
| `simplesamlphp-2.5.3.1-idp-metadata-2026-09-30.xml` | the identity provider's metadata, as served | its URL | no |
| `simplesamlphp-2.5.3.1-sp-metadata-2026-09-30.xml` | the service provider's metadata, as served | its URL | no |
| `simplesamlphp-2.5.3.1-sp-authnrequest-2026-09-30.xml` | the service provider's `AuthnRequest` | HTTP-Redirect | over the query string, rsa-sha256, valid under the service provider's metadata; no XML signature, which the binding removes |
| `simplesamlphp-2.5.3.1-idp-response-signed-both-2026-09-30.xml` | the response to it, default configuration | HTTP-POST | the assertion, then the response over it |
| `simplesamlphp-2.5.3.1-idp-response-signed-assertion-2026-09-30.xml` | the response of the second configuration, answering the second login's `AuthnRequest` (`_7cc71f776e69f4f4cdb3fba9ebc8392b9491d4e6e4`, not kept) | HTTP-POST | the assertion only |
| `simplesamlphp-2.5.3.1-sp-logoutrequest-2026-09-30.xml` | the service provider's `LogoutRequest` | HTTP-Redirect | over the query string, rsa-sha256, valid under the service provider's metadata; no XML signature |
| `simplesamlphp-2.5.3.1-idp-logoutresponse-2026-09-30.xml` | the identity provider's `LogoutResponse` | HTTP-Redirect | not at all: no `Signature` in the query string, no XML signature (finding F-1) |

## 3. xmlsec1

`xmlsec1-verify.sh <directory> [<glob>]` verifies every XML signature of the batch with xmlsec1: the certificate of
each `md:EntityDescriptor` of the batch (its first `KeyDescriptor` whose `use` is `signing` or absent) is written as
PEM, and each signature is verified with `--pubkey-cert-pem` under the certificate of the metadata of its signer, a
message's under its `Issuer`'s, an assertion's under its own `Issuer`'s, a signed metadata document's under its own.
The SAML `ID` attributes are declared to xmlsec1 (`--id-attr:ID` on `Assertion`, `Response`, `AuthnRequest`,
`LogoutRequest`, `LogoutResponse`, `EntityDescriptor`), and each signature is named with `--node-xpath`, so that a
response signed over its signed assertion has both verified, as `xml-security`'s `verify-every-scheme.sh` does. A
document without an XML signature is listed as `SKIP`; a batch where no signature verifies fails.

On 30 September 2026, xmlsec1 1.3.7 on the library's nine files: eight signatures verified (the two of the doubly
signed response included), the two unsigned metadata skipped, exit status 0. On a copy of the doubly signed
response with one attribute value changed, both signatures failed with `Failure reason: REFERENCE`. With the
service provider's metadata carrying the identity provider's certificate instead of its own, the `AuthnRequest`
failed with `Failure reason: SIGNATURE`, although its `KeyInfo` carries the right certificate: xmlsec1 verifies
under the key it is given, not under the message's `KeyInfo`.

On the installation's captures:

```
docker run --rm -v "$PWD:/project:ro" -w /project alpine:3.22 sh -c 'apk add -q xmlsec libxml2-utils \
    && sh tests/Interop/simplesamlphp/xmlsec1-verify.sh tests/Fixture/real "simplesamlphp-2.5.3.1-*.xml"'
```

On 30 September 2026: three signatures verified under the identity provider's metadata, the assertion's of the
response of the second configuration and both of the doubly signed response, exit status 0; the two metadata and
the three documents HTTP-Redirect carried skipped, having no XML signature. The signatures of the `AuthnRequest` and
of the `LogoutRequest` are over the query string, not over XML: xmlsec1 has nothing to verify there, and
`capture.sh` verified them with OpenSSL (`openssl_verify()`) under the service provider's metadata, as step 2 says.

## 4. Measurements

`measure.php` reads the documents with plain DOM, by direct children, nothing of SimpleSAMLphp, and prints the
tables below; the windows are in seconds from the assertion's `IssueInstant`, `SessionNotOnOrAfter` with the
`AuthnInstant` beside it. On 30 September 2026:

```
docker run --rm -v "$PWD:/project:ro" -w /project ghcr.io/spomky-labs/phpqa:8.4 \
    php tests/Interop/simplesamlphp/measure.php tests/Fixture/real 'simplesamlphp-*.xml'
```

| Document | Bytes | Root | XML signatures | Signature, digest, canonicalization | PrefixList | Times, fractional digits | ID | Destination | Issuer Format | Other |
|---|---|---|---|---|---|---|---|---|---|---|
| `simplesamlphp-2.5.3.1-idp-logoutresponse-2026-09-30.xml` | 586 | LogoutResponse | none |  |  | 0 | `_` and 42 hexadecimal digits | present | omitted | status Success |
| `simplesamlphp-2.5.3.1-idp-response-signed-assertion-2026-09-30.xml` | 4 869 | Response | Assertion | rsa-sha256, sha256, xml-exc-c14n (transforms enveloped-signature xml-exc-c14n) | none | 0 | `_` and 42 hexadecimal digits | present | omitted | status Success |
| `simplesamlphp-2.5.3.1-idp-response-signed-both-2026-09-30.xml` | 7 216 | Response | Response, Assertion | rsa-sha256, sha256, xml-exc-c14n (transforms enveloped-signature xml-exc-c14n) | none | 0 | `_` and 42 hexadecimal digits | present | omitted | status Success |
| `simplesamlphp-2.5.3.1-sp-authnrequest-2026-09-30.xml` | 599 | AuthnRequest | none |  |  | 0 | `_` and 42 hexadecimal digits | present | omitted | AssertionConsumerServiceURL="http://localhost:8082/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp", ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" |
| `simplesamlphp-2.5.3.1-sp-logoutrequest-2026-09-30.xml` | 727 | LogoutRequest | none |  |  | 0 | `_` and 42 hexadecimal digits | present | omitted | NameID (SPNameQualifier Format), SessionIndex |
| `simplesamlphp-saml2-4.20.3-authnrequest-signed-2026-09-30.xml` | 2 881 | AuthnRequest | AuthnRequest | rsa-sha256, sha256, xml-exc-c14n (transforms enveloped-signature xml-exc-c14n) | none | 0 | 26 characters | present | omitted | AssertionConsumerServiceURL="https://sp.example.org/acs", ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", NameIDPolicy (Format AllowCreate) |
| `simplesamlphp-saml2-4.20.3-logoutrequest-signed-2026-09-30.xml` | 2 876 | LogoutRequest | LogoutRequest | rsa-sha256, sha256, xml-exc-c14n (transforms enveloped-signature xml-exc-c14n) | none | 0 | 27 characters | present | omitted | NameID (SPNameQualifier Format), SessionIndex |
| `simplesamlphp-saml2-4.20.3-logoutresponse-signed-2026-09-30.xml` | 2 808 | LogoutResponse | LogoutResponse | rsa-sha256, sha256, xml-exc-c14n (transforms enveloped-signature xml-exc-c14n) | none | 0 | 28 characters | present | omitted | status Success |
| `simplesamlphp-saml2-4.20.3-response-signed-assertion-2026-09-30.xml` | 4 477 | Response | Assertion | rsa-sha256, sha256, xml-exc-c14n (transforms enveloped-signature xml-exc-c14n) | none | 0 | 22 characters | present | omitted | status Success |
| `simplesamlphp-saml2-4.20.3-response-signed-both-2026-09-30.xml` | 6 775 | Response | Response, Assertion | rsa-sha256, sha256, xml-exc-c14n (transforms enveloped-signature xml-exc-c14n) | none | 0 | 22 characters | present | omitted | status Success |

| Response | NameID | Conditions NotBefore, NotOnOrAfter | Bearer NotOnOrAfter | SessionNotOnOrAfter | AudienceRestriction (Audience) | SessionIndex | Attributes, most values | NameFormat | xsi:type on values | AuthnContextClassRef |
|---|---|---|---|---|---|---|---|---|---|---|
| `simplesamlphp-2.5.3.1-idp-response-signed-assertion-2026-09-30.xml` | transient, 43 characters, SPNameQualifier | -30 s, +300 s | +300 s | +28800 s (AuthnInstant +0 s) | 1 (1) | 43 characters | 2, 2 | uri | xs:string | Password |
| `simplesamlphp-2.5.3.1-idp-response-signed-both-2026-09-30.xml` | transient, 43 characters, SPNameQualifier | -30 s, +300 s | +300 s | +28800 s (AuthnInstant +0 s) | 1 (1) | 43 characters | 2, 2 | uri | xs:string | Password |
| `simplesamlphp-saml2-4.20.3-response-signed-assertion-2026-09-30.xml` | transient, 23 characters, SPNameQualifier | -30 s, +300 s | +300 s | +28790 s (AuthnInstant -10 s) | 1 (1) | 21 characters | 2, 2 | basic | xs:string | Password |
| `simplesamlphp-saml2-4.20.3-response-signed-both-2026-09-30.xml` | transient, 23 characters, SPNameQualifier | -30 s, +300 s | +300 s | +28790 s (AuthnInstant -10 s) | 1 (1) | 21 characters | 2, 2 | basic | xs:string | Password |

| Metadata | Bytes | entityID length | Role, flags | KeyDescriptor | Endpoints | NameIDFormat | Other |
|---|---|---|---|---|---|---|---|
| `simplesamlphp-2.5.3.1-idp-metadata-2026-09-30.xml` | 3 813 | 61 | IDPSSODescriptor | signing (1 certificate), encryption (1 certificate) | SingleLogoutService HTTP-Redirect, SingleSignOnService HTTP-Redirect | transient | IDPSSODescriptor@errorURL |
| `simplesamlphp-2.5.3.1-sp-metadata-2026-09-30.xml` | 4 212 | 71 | SPSSODescriptor AuthnRequestsSigned="true" | signing (1 certificate), encryption (1 certificate) | SingleLogoutService HTTP-Redirect, AssertionConsumerService HTTP-POST index 0, AssertionConsumerService HTTP-Artifact index 1 |  | SPSSODescriptor/Extensions |
| `simplesamlphp-saml2-4.20.3-idp-metadata-2026-09-30.xml` | 1 989 | 23 | IDPSSODescriptor | signing (1 certificate) | SingleLogoutService HTTP-Redirect, SingleSignOnService HTTP-Redirect | transient | ID |
| `simplesamlphp-saml2-4.20.3-idp-metadata-signed-2026-09-30.xml` | 4 291 | 23 | IDPSSODescriptor | signing (1 certificate) | SingleLogoutService HTTP-Redirect, SingleSignOnService HTTP-Redirect | transient | ID, Signature first child: rsa-sha256, sha256, xml-exc-c14n (transforms enveloped-signature xml-exc-c14n), PrefixList none |
| `simplesamlphp-saml2-4.20.3-sp-metadata-2026-09-30.xml` | 2 049 | 22 | SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" | signing (1 certificate) | SingleLogoutService HTTP-Redirect, AssertionConsumerService HTTP-POST index 0 | transient | ID |
| `simplesamlphp-saml2-4.20.3-sp-metadata-signed-2026-09-30.xml` | 4 350 | 22 | SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" | signing (1 certificate) | SingleLogoutService HTTP-Redirect, AssertionConsumerService HTTP-POST index 0 | transient | ID, Signature first child: rsa-sha256, sha256, xml-exc-c14n (transforms enveloped-signature xml-exc-c14n), PrefixList none |

What the tables cannot show, from `capture.sh` and the sources of SimpleSAMLphp 2.5.3.1:

- The `AuthnRequest` and the `LogoutRequest` of the installation carried an rsa-sha256 signature over the query
  string, valid under the service provider's metadata; its `LogoutResponse` carried none (F-1).
- SimpleSAMLphp writes every time to the second, in UTC with `Z`: no fractional digit anywhere, the library's
  documents included.
- The windows of the installation are its defaults: `NotBefore` 30 s before the issue instant, `NotOnOrAfter` and the
  bearer `NotOnOrAfter` 300 s after (`assertion.lifetime`), `SessionNotOnOrAfter` 8 h after the `AuthnInstant`
  (`session.duration`); the `AuthnInstant` fell in the same second as the issue instant. The messages of one login
  were issued within 3 s of each other.
- Its service provider accepts a clock skew of `assertion.allowed_clock_skew`, 180 s by default, clamped to 180 to
  300 s (`modules/saml/src/Message.php`): the default and the ceiling of `TimeBounds::$clockSkew` (section 7).
- IDs are `_` and 42 hexadecimal digits, 168 bits, for the messages, the assertion, the `SessionIndex` and the
  transient `NameID` alike (43 characters, under the 128 bytes of `maxIdLength` and the 256 characters of M-12).

Against the provisional bounds of section 7, on these documents: one `AudienceRestriction` of one `Audience` (bounds
8 and 16), two attributes of at most two values (256 and 256), one `SessionIndex` (16), per metadata role one signing
and one encryption certificate (16 and 16), at most two endpoints of one kind (64), at most one `NameIDFormat` (16);
a bearer window of 300 s (`maxBearerWindow` 3 600 s); entity IDs of 61 and 71 characters (1 024). The performance
figure of section 9.6 needs the model's code and is not measured here.

## 5. Findings

Each document of section 4 read against sections 4, 6, 7 and 8 of `spec/model.md`, with a clock frozen at its
issue instant and the metadata of its batch. None of the library's nine documents would be refused: every
signature the profile requires is there, `Destination` and `Recipient` name the assertion consumer service of
the service provider's metadata, the `Audience` its entity ID, the `InResponseTo` the request, the windows are
bounded, the formats are of Core §8.2 and §8.3. The installation's documents give the following.

- **F-1. The identity provider's `LogoutResponse` is not signed, and the model refuses it.** SimpleSAMLphp 2.5.3.1
  signs a logout message only when `sign.logout` or `redirect.sign` is set (`addRedirectSign()` of
  `modules/saml/src/Message.php`, `false` by default), and its identity provider sets neither by default: the
  `LogoutResponse` travels over HTTP-Redirect with no `Signature` parameter and no XML signature. The model refuses
  it with `SignatureRequired`: `LogoutResponseValidator::validate()` requires a `ds:Signature` (M-2, section 6.4 by
  way of 6.3, Profiles §4.4.4.2), and `validateAuthenticatedByBinding()` does not apply, since the binding carried no
  signature for `saml2-bindings` to verify (section 6.8). The producer is wrong and the rule stands (section 9.4):
  the fix is SimpleSAMLphp's `sign.logout => true`, in `saml20-idp-hosted.php` or in the `saml20-sp-remote.php` entry
  of the peer. Phase 2 needs it on the installation's identity provider for the model's service provider to accept
  its logout answer, a non-default setting to add then with this reason; the same holds for the `LogoutRequest` that
  identity provider would send in a logout it starts. SimpleSAMLphp's own service provider accepted the unsigned
  answer (`redirect.validate` is `false` by default).
- **F-2. SimpleSAMLphp signs the response by default.** `saml20.sign.response` defaults to `true` (section 2), so
  the default capture is the doubly signed response and the configured one is the response whose assertion alone is
  signed. Section 9.4 of the specification says the reverse ("a response signed over it where the installation is
  configured to"): its wording, not a rule, is what the capture contradicts. The branch of M-2 that SimpleSAMLphp's
  defaults leave aside is still the response signed alone, Keycloak's (section 9.5).
- **F-3. SimpleSAMLphp's service provider accepts a response whose own signature fails, when its assertion's holds.**
  The probe of `capture.sh` (step 7) moved the response's `IssueInstant` by one second: xmlsec1 then fails the
  response's signature (`Failure reason: REFERENCE`) and verifies the assertion's, and the service provider accepted
  the response and returned to its `ReturnTo`. The constructor of `SAML2\Message` swallows a signature that fails
  its digest, `validate()` then answers `false` as for an unsigned message, and `processResponse()` asks for one
  valid signature among the response's and the assertion's. The model refuses the same document (M-2: every
  signature present verifies; section 6.1 step 3, `Dsig`'s `DigestMismatch`), which the hostile corpus of section 9.2
  already asserts for the reverse case. Nothing changes in the model, but SimpleSAMLphp's acceptance is no proof that
  every signature of a document holds: phase 2 runs `verify.php` and `xmlsec1-verify.sh` on what the writers produce,
  both of which fail a document with one failing signature, as well as posting it (decision 0013: a target, not an
  oracle). The same constructor makes a posted `AuthnRequest` or `LogoutRequest` whose XML signature fails read as
  unsigned, processed when the configuration does not require a signature.
- **F-4. What HTTP-Redirect carried has no XML signature, by construction.** The `AuthnRequest` and the
  `LogoutRequest` of the installation are signed over the query string (SAML Bindings section 3.4.4.1), which
  `capture.sh` verified: the model reads them through `validateAuthenticatedByBinding()` (sections 6.2 step 2 and
  6.3), and `validate()` refuses them with `SignatureRequired`, the `AuthnRequest` because the service provider's
  metadata says `AuthnRequestsSigned="true"`. The raw query strings are not kept; the judge of `saml2-bindings` will
  want them, which a later capture can keep next to the XML.
- **F-5. Attribute names under the `uri` format are not URIs.** The identity provider's default `attributes.NameFormat`
  is `urn:oasis:names:tc:SAML:2.0:attrname-format:uri` (`getAttributeNameFormat()` of
  `modules/saml/src/IdP/SAML2.php`), while the names of the test user are bare `uid` and `eduPersonAffiliation`: the
  distributed example of `saml20-idp-hosted.php` maps them to OIDs with `core:AttributeMap` `name2oid`, which this
  installation leaves out. The model accepts it, since section 6.1 step 11 checks that the `NameFormat` is one of
  Core §8.2 and says nothing of the form of the `Name`; a later rule that read the `Name` under `uri` as an absolute
  URI (M-6) would refuse SimpleSAMLphp's default document.
- **F-6. `xsi:type="xs:string"` on every value.** Both the library and the installation write it on each
  `AttributeValue`, with `xmlns:xs` and `xmlns:xsi` declared on the `saml:Assertion`, the case of dsig.md §6.3 and of
  the behaviour row of section 9.3.
- **F-7. The metadata as SimpleSAMLphp publishes it.** Unsigned (`metadata.sign.enable` is `false`): the model reads
  it with `readTrusted()` only, and `readSigned()` is exercised on the library's signed metadata. The service
  provider's carries `md:Extensions` (an `idpdisc:DiscoveryResponse`), accepted and not read (M-5), and an HTTP-Artifact
  assertion consumer service at index 1, dropped next to the HTTP-POST one at index 0 (section 6.5 step 6); the
  identity provider's carries `errorURL` on its `IDPSSODescriptor`, not read. Both publish their one certificate as
  a signing and as an encryption `KeyDescriptor`. Both are indented, with whitespace-only text nodes between the
  elements, which `Core` keeps (I-15) and the strict readers of the model have to pass over.
- **F-8. The library the installation runs.** SimpleSAMLphp 2.5.3.1 processes every message with
  `saml2-legacy` 4.20.3, on `xmlseclibs` 3.1.5; `simplesamlphp/saml2` 6.2.4, on `simplesamlphp/xml-security`, is
  imported for its constants only (section 1). The library half follows the installation; a release of SimpleSAMLphp
  that moves its messages to the 6.x library would need both halves run again, which section 12 already asks at
  every change of SimpleSAMLphp's version.

For the repository, outside this directory: nothing marks the fixtures of `tests/Fixture/` as binary, while
`xml-security` carries `/tests/Core/Fixture/** -text` in its `.gitattributes` (story #3 owns that file; the files
here were committed without conversion, `core.autocrlf` unset); and `tests/Fixture/real/README.md`, which section 10
asks for, is not written here, its owner can point to this file for the SimpleSAMLphp documents. The PHP of this
directory runs in its own containers and uses what section 8 bans in the package (`DOMDocument`, `loadXML()`,
`saveXML()`, `getElementsByTagNameNS()`, `textContent`, `DOMXPath`, `echo`): the toolchain of story #3 has to leave
`tests/Interop/` out, as `xml-security` leaves its interoperability project out (`excludePaths` of
`.ci-tools/phpstan.neon` and `withSkip()` of `.ci-tools/rector.php` on `tests/*/Fixture/*`, `excludes` of
`mago.toml`), and `library/composer.json` is a Composer project of its own, which a dependency update tool would
otherwise pick up.
