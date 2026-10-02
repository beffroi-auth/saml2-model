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
| `exchange.php` | the exchange of phase 2: the model and the installation, both ways, login and logout, and four probes; it writes the model's documents to `written/` and what SimpleSAMLphp sent to `received/` (both ignored), or to `tests/Fixture/real/` with `--keep` |
| `timing.php` | the figure of section 9.6 of the specification, measured on SimpleSAMLphp's real responses |
| `.castor/simplesamlphp.php`, at the root | `castor simplesamlphp`: every step above from one task |

Phase 1 of story #11, on 30 September 2026, built what does not need the model's code: the test keys, the library
half, the installation half and the captures (sections 1 to 5). Phase 2, the same day, played the exchange with the
model's writers and validators, both ways, on the running installation (section 6).

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
| The model in the exchange | this repository, `src/` as of `e11e945`, on `beffroi-php/xml-security` `dev-main` at `d7990c060cd0` | the branch `story/11-simplesamlphp` and `composer.lock` | 30 September 2026 |
| PHP of the exchange | 8.5.10 and 8.4.25, curl 8.14.1 | `ghcr.io/spomky-labs/phpqa:8.5` and `:8.4`, `PHP_VERSION` of castor | 30 September 2026 |
| Castor | 1.7.0 | the machine that ran it | 30 September 2026 |

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
figure of section 9.6 needs the model's code: phase 2 measures it (section 6).

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

## 6. Phase 2: the exchange with the model

On 30 September 2026, `exchange.php` played both directions against the installation of section 2 with the package
of this repository, the test keys of `tests/Fixture/keys/` and the live clock: the model as identity provider behind
SimpleSAMLphp's service provider, the model as service provider in front of SimpleSAMLphp's identity provider, login
and logout both ways. Every step was green on PHP 8.5.10 and on PHP 8.4.25; four probes showed that SimpleSAMLphp
refuses the model's documents once changed after signing, so that its acceptance of the genuine ones proves a
signature it verified; `verify.php` and xmlsec1 verified every document the model wrote. What SimpleSAMLphp sent is
committed under `tests/Fixture/real/` and accepted by `tests/Unit/Interop/SimpleSamlPhpDocumentsTest.php`. The phase
took under an hour of the four hours it was given.

### Commands

```
# The whole exchange from a clean checkout: the package's dependencies and the library half installed when they are
# missing, the installation up in the configuration of the exchange, the exchange, verify.php and xmlsec1 on every
# document the model wrote, the installation down. PHP 8.5 by default, PHP_VERSION=8.4 for the other.
castor simplesamlphp

# The same, and what SimpleSAMLphp sent kept in tests/Fixture/real/, dated, instead of received/
castor simplesamlphp --keep

# Each step alone
castor simplesamlphp --up                 # the installation in the configuration of the exchange, SSP_EXCHANGE=true
castor simplesamlphp --exchange [--keep]  # the exchange, the installation up
castor simplesamlphp --verify             # verify.php and xmlsec1 on written/, the model's documents of the last run
castor simplesamlphp --verify --in=tests/Fixture/real --glob='simplesamlphp-saml2-4.20.3-*.xml'   # section 1's batch
castor simplesamlphp --produce            # the library writes its fixtures (section 1)
castor simplesamlphp --capture            # capture.sh (section 2)
castor simplesamlphp --down

# What --exchange runs, from the root of the repository
docker run --rm --network saml2-model-simplesamlphp_default --user "$(id -u):$(id -g)" \
    -e EXCHANGE_CONNECT_TO=localhost:8081:idp:80,localhost:8082:sp:80 -v "$PWD:/project" -w /project \
    ghcr.io/spomky-labs/phpqa:8.5 php tests/Interop/simplesamlphp/exchange.php [--keep]

# The figure of section 9.6, on each PHP of the CI
docker run --rm -v "$PWD:/project:ro" -w /project ghcr.io/spomky-labs/phpqa:8.5 php tests/Interop/simplesamlphp/timing.php
```

The exchange runs in the phpqa image on the network of the installation: `EXCHANGE_CONNECT_TO` pins `localhost:8081`
and `localhost:8082` to the two containers at the connection, so that the `Host` header, every entity ID, every
`Destination` and every cookie stay those a browser on the machine sees.

### The model's side

The script is the model's side of the wire, and stands in for `saml2-bindings` (section 6.8 of the specification),
which does not exist yet: a browser with one cookie jar per login, which never follows a redirect by itself; for what
HTTP-Redirect carries to the model, the signature over the query string, the octets of `SAMLRequest`, `RelayState`
and `SigAlg` in that order and as they appear in the URL, verified with `Verifier::verifyDetached()` under the keys of
the sender's metadata, then the message base64-decoded and raw-inflated; for what the model sends, the form encoding
of HTTP-POST, the message base64-encoded in a form field and the `RelayState` sent back as received. The model's two
roles answer at `http://localhost:8083/model/`, where nothing listens: the script intercepts every message addressed
there.

| Role | Entity ID | Endpoints | Flags | Signing key |
|---|---|---|---|---|
| identity provider | `http://localhost:8083/model/idp` | `SingleSignOnService` `.../idp/sso` and `SingleLogoutService` `.../idp/slo`, HTTP-Redirect | `WantAuthnRequestsSigned="true"`, `NameIDFormat` transient | `idp-signing-key.pem` |
| service provider | `http://localhost:8083/model/sp` | `AssertionConsumerService` `.../sp/acs`, HTTP-POST, index 0, default; `SingleLogoutService` `.../sp/slo`, HTTP-POST | `AuthnRequestsSigned="true"`, `WantAssertionsSigned="true"`, `NameIDFormat` transient | `sp-signing-key.pem` |

`MetadataWriter` writes both metadata, signed with the key of their role, into `written/`, before the first request:
SimpleSAMLphp parses its metadata at every request. Every writer signs without `KeyInfo` (`Signing::$certificatePem`
left `null`). The validators read the clock of the machine; the replay store is `InMemoryReplayGuard` of
`tests/Support/`.

### Configuration added

Everything of section 2 stands; the exchange adds the settings below. None changes what `capture.sh` plays: the
third configuration is off unless `SSP_EXCHANGE=true`, the model's entries exist only once `written/` holds its
metadata, and `default-sp` is left as it was.

| Where | Setting | Value | Why |
|---|---|---|---|
| `compose.yaml` | a volume on both parties | `../written` at `/var/simplesamlphp/model`, read-only | the metadata the model wrote |
| `compose.yaml`, `saml20-idp-hosted.php` | with `SSP_EXCHANGE=true`, the third configuration: `SingleSignOnServiceBinding`, `SingleLogoutServiceBinding` | HTTP-Redirect and HTTP-POST, at the same locations | the model posts its signed `AuthnRequest` and `LogoutRequest` over HTTP-POST; SimpleSAMLphp publishes HTTP-Redirect alone by default (`getGenerated()` of `src/SimpleSAML/Metadata/MetaDataStorageHandler.php`) (F-10) |
| `saml20-sp-remote.php` | the model's service provider | read from `model-sp-metadata.xml` by `SAMLParser::parseDescriptorsString()` and `getMetadata20SP()` | SimpleSAMLphp reads what the model writes, with the parser of its XML metadata sources and of metarefresh; `AuthnRequestsSigned="true"` becomes `validate.authnrequest`, `WantAssertionsSigned="true"` `saml20.sign.assertion` |
| `saml20-sp-remote.php`, the model's entry only | `sign.logout` | `true` | F-1: the identity provider signs its logout messages to the model, which refuses an unsigned one (M-2) |
| `saml20-sp-remote.php`, the model's entry only | `validate.logout` | `true` | F-9: without it, a logout message whose signature fails is accepted as an unsigned one |
| `saml20-idp-remote.php` | the model's identity provider | read from `model-idp-metadata.xml` by `getMetadata20IdP()`, nothing added | the same parser; `WantAuthnRequestsSigned="true"` becomes `sign.authnrequest` |
| service provider `authsources.php` | `for-model`, a second `saml:SP` | its entity ID `http://localhost:8082/simplesaml/module.php/saml/sp/metadata/for-model`, `idp` the model's, `sp.pem` and `sp.crt`, `sign.authnrequest` and `sign.logout` `true` | a service provider that logs in at the model's identity provider, `default-sp` left as phase 1 captured it |
| `for-model` | `SingleLogoutServiceBinding` | HTTP-Redirect and HTTP-POST | a service provider publishes HTTP-Redirect, and SOAP with an SQL store, by default (`getSLOEndpoints()` of `modules/saml/src/Auth/Source/SP.php`); the model answers over HTTP-POST (F-10) |
| `for-model` | `validate.logout` | `true` | F-9 |
| `sp/session.php`, mounted into `public/` | a page | the session of `for-model` as JSON: its identity provider, `NameID`, `SessionIndex` and attributes, or `401` | the proof that the service provider opened its session with what the model sent |

### Results

The run kept, `castor simplesamlphp --keep` on PHP 8.5.10 at 13:07 UTC, its documents issued between 13:07:34 and
13:07:35; `PHP_VERSION=8.4 castor simplesamlphp` at 13:13 UTC gave the same outcome on PHP 8.4.25, every step green.

**The model as identity provider, SimpleSAMLphp's service provider `for-model` in front.**

1. `GET` `for-model`'s login URL, `ReturnTo` its `session.php`: a redirect to `http://localhost:8083/model/idp/sso`
   carrying `SAMLRequest`, `RelayState`, `SigAlg` (rsa-sha256) and `Signature`. The script read `for-model`'s
   metadata from its URL with `MetadataReader::readTrusted()`, verified the query string under its key, and
   `AuthnRequestValidator::validateAuthenticatedByBinding()` accepted the request (`_ef4cb04a...` in the run kept),
   `Authentication::Binding`, its assertion consumer service resolved to the HTTP-POST one of `for-model`'s metadata,
   index 0.
2. `ResponseWriter` answered with the identity provider's test key, a transient `NameID` whose `SPNameQualifier` is
   `for-model`, `uid` = `model-student` and `eduPersonAffiliation` = `member`, `student` under the `basic` name
   format, without `xsi:type` (section 6.6), SimpleSAMLphp's own windows (`NotBefore` 30 s back, 300 s ahead, a
   session of 8 h): once with the assertion signed (`SignedParts::Assertion`), once with the response signed over it
   (`SignedParts::AssertionAndResponse`), each after a login of its own. Posted with the `RelayState` to the
   assertion consumer service, each was answered with a redirect to `session.php`, which showed the session open with
   the model's identity provider, the `NameID` and the `SessionIndex` the model issued, and exactly the attributes it
   sent.
3. `GET` `for-model`'s logout URL: a redirect to `http://localhost:8083/model/idp/slo`, its query string signed;
   verified the same way, `LogoutRequestValidator::validateAuthenticatedByBinding()` accepted the `LogoutRequest`
   (`_b00d8f15...`), whose `NameID` and `SessionIndex` are those the model issued. `LogoutResponseWriter` answered,
   signed, to `for-model`'s HTTP-POST single logout service, the `RelayState` sent back: a redirect to `session.php`,
   which then answered `401`, the session closed.

**The model as service provider, SimpleSAMLphp's identity provider in front.**

1. The identity provider's metadata read live from its URL with `readTrusted()`. `AuthnRequestWriter` wrote the
   request (`_627d4a4e...`), signed with the service provider's test key, its `Destination` the HTTP-POST single
   sign-on service of that metadata, an `AssertionConsumerServiceURL`, `ProtocolBinding` HTTP-POST and a
   `NameIDPolicy` transient with `AllowCreate`; posted with the `RelayState` `model-login`. The identity provider took
   it to its login form, the test user logged in, and the page that followed held the HTTP-POST form of its response,
   addressed to `http://localhost:8083/model/sp/acs` with the `RelayState` `model-login`.
2. `ResponseValidator` accepted the response (`_117a92c3...`) under that metadata, with
   `ExpectedResponse::toRequest()` naming the request: `SignatureCoverage::AssertionAndResponse`, a transient `NameID`
   whose `SPNameQualifier` is the model's service provider, `uid` = `test` and `eduPersonAffiliation` = `member`,
   `student`.
3. `LogoutRequestWriter` wrote the logout (`_4155d5bb...`), signed, naming that `NameID` and that `SessionIndex`,
   posted to the HTTP-POST single logout service. The identity provider answered with the HTTP-POST form of its
   `LogoutResponse` (`_8496a6eb...`) to `http://localhost:8083/model/sp/slo`, signed in the XML since the model's
   entry sets `sign.logout`: `LogoutResponseValidator::validate()` accepted it, `Authentication::XmlSignature`, status
   `Success`.

### Probes

Each probe posts a document of the model changed after signing where its genuine twin was accepted, and must be
refused; none is written to `written/`. SimpleSAMLphp's error page names the exception (`showerrors` is `true` by
default), which the script prints.

| Probe | Posted to | SimpleSAMLphp's answer |
|---|---|---|
| a response with its signed assertion, `model-student` changed to `model-teacher` in it | `for-model`'s assertion consumer service | HTTP 500, `Exception: Reference validation failed` |
| a `LogoutResponse`, its `IssueInstant` one second later | `for-model`'s single logout service, its logout pending | HTTP 500, `SimpleSAML\Error\Exception: Validation of received messages enabled, but no signature found on message.` |
| a `LogoutRequest`, its `IssueInstant` one second later | the identity provider's single logout service, logged in | the same |
| an `AuthnRequest`, its `IssueInstant` one second later | the identity provider's single sign-on service | the same |

"No signature found" is how SimpleSAMLphp reports a signature that failed: the constructor of `SAML2\Message`
swallows it (F-3), and `validate.logout` or `validate.authnrequest` then asks for one. With `validate.logout` removed
from both sides, and nothing else changed, on the same day, the two logout probes were accepted: `for-model` answered
with a redirect to `session.php`, the identity provider with a redirect to its `logout-resume` (F-9).

### The model's documents, verified

`castor simplesamlphp` hands `written/` to the library half and to xmlsec1 once the exchange is over: the seven
documents the model wrote in the run, both metadata signed, the response with its signed assertion, the response
signed over it, the `LogoutResponse`, the `AuthnRequest` and the `LogoutRequest`. On each of the two runs above:

```
OK   model-idp-logoutresponse.xml: LogoutResponse from http://localhost:8083/model/idp, LogoutResponse signature valid under idp-signing-certificate.pem
OK   model-idp-metadata.xml: metadata of http://localhost:8083/model/idp, certificates idp-signing-certificate.pem, signature valid under idp-signing-certificate.pem
OK   model-idp-response-signed-assertion.xml: Response from http://localhost:8083/model/idp, assertion signature valid under idp-signing-certificate.pem
OK   model-idp-response-signed-both.xml: Response from http://localhost:8083/model/idp, Response signature valid under idp-signing-certificate.pem, assertion signature valid under idp-signing-certificate.pem
OK   model-sp-authnrequest.xml: AuthnRequest from http://localhost:8083/model/sp, AuthnRequest signature valid under sp-signing-certificate.pem
OK   model-sp-logoutrequest.xml: LogoutRequest from http://localhost:8083/model/sp, LogoutRequest signature valid under sp-signing-certificate.pem
OK   model-sp-metadata.xml: metadata of http://localhost:8083/model/sp, certificates sp-signing-certificate.pem, signature valid under sp-signing-certificate.pem
7 documents, 0 failed
...
8 signatures verified by xmlsec1 1.3.7 (openssl), 0 failed
```

The documents themselves are not committed: a run writes new IDs and times, and the round trips of section 9.1 of the
specification already commit what the writers produce.

### Captures

What SimpleSAMLphp sent the model in the run kept, bytes as received (HTTP-POST base64-decoded, HTTP-Redirect
URL-decoded, base64-decoded and raw-inflated, as in section 2), and the two query strings as they appeared in the URL.

| File under `tests/Fixture/real/` | What | Carried by | Signed |
|---|---|---|---|
| `simplesamlphp-2.5.3.1-idp-metadata-exchange-2026-09-30.xml` | the identity provider's metadata in the third configuration, as served | its URL | no |
| `simplesamlphp-2.5.3.1-sp-metadata-for-model-2026-09-30.xml` | `for-model`'s metadata, as served | its URL | no |
| `simplesamlphp-2.5.3.1-sp-authnrequest-to-model-2026-09-30.xml`, `...-query-...txt` | `for-model`'s `AuthnRequest` to the model, and its query string | HTTP-Redirect | over the query string, rsa-sha256 |
| `simplesamlphp-2.5.3.1-sp-logoutrequest-to-model-2026-09-30.xml`, `...-query-...txt` | `for-model`'s `LogoutRequest` to the model, and its query string | HTTP-Redirect | over the query string, rsa-sha256 |
| `simplesamlphp-2.5.3.1-idp-response-to-model-2026-09-30.xml` | the identity provider's response to the model's `AuthnRequest` | HTTP-POST | the assertion, then the response over it |
| `simplesamlphp-2.5.3.1-idp-logoutresponse-to-model-2026-09-30.xml` | the identity provider's `LogoutResponse` to the model's `LogoutRequest` | HTTP-POST | the `LogoutResponse`, `sign.logout` |

`tests/Unit/Interop/SimpleSamlPhpDocumentsTest.php` accepts them with a clock frozen at their `IssueInstant`: the
response and the `LogoutResponse` through `validate()`, under the identity provider's metadata; the two requests
through `validateAuthenticatedByBinding()`, after verifying again the signature of their query string with
`Verifier::verifyDetached()` under `for-model`'s metadata and checking that the XML kept is what that query string
carried. xmlsec1 verifies the three signatures of the two HTTP-POST documents under the identity provider's metadata:

```
docker run --rm -v "$PWD:/project:ro" -w /project alpine:3.22 sh -c 'apk add -q xmlsec libxml2-utils \
    && sh tests/Interop/simplesamlphp/xmlsec1-verify.sh tests/Fixture/real "simplesamlphp-2.5.3.1-*.xml"'
```

On 30 September 2026: six signatures verified, the three of section 3 and these three, exit status 0.

### Measurements

`measure.php` on the captures of the exchange (section 4 has its command):

| Document | Bytes | Root | XML signatures | Signature, digest, canonicalization | PrefixList | Times, fractional digits | ID | Destination | Issuer Format | Other |
|---|---|---|---|---|---|---|---|---|---|---|
| `simplesamlphp-2.5.3.1-idp-logoutresponse-to-model-2026-09-30.xml` | 2 886 | LogoutResponse | LogoutResponse | rsa-sha256, sha256, xml-exc-c14n (transforms enveloped-signature xml-exc-c14n) | none | 0 | `_` and 42 hexadecimal digits | present | omitted | status Success |
| `simplesamlphp-2.5.3.1-idp-response-to-model-2026-09-30.xml` | 7 046 | Response | Response, Assertion | rsa-sha256, sha256, xml-exc-c14n (transforms enveloped-signature xml-exc-c14n) | none | 0 | `_` and 42 hexadecimal digits | present | omitted | status Success |
| `simplesamlphp-2.5.3.1-sp-authnrequest-to-model-2026-09-30.xml` | 560 | AuthnRequest | none |  |  | 0 | `_` and 42 hexadecimal digits | present | omitted | AssertionConsumerServiceURL="http://localhost:8082/simplesaml/module.php/saml/sp/saml2-acs.php/for-model", ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" |
| `simplesamlphp-2.5.3.1-sp-logoutrequest-to-model-2026-09-30.xml` | 691 | LogoutRequest | none |  |  | 0 | `_` and 42 hexadecimal digits | present | omitted | NameID (SPNameQualifier Format), SessionIndex |

| Response | NameID | Conditions NotBefore, NotOnOrAfter | Bearer NotOnOrAfter | SessionNotOnOrAfter | AudienceRestriction (Audience) | SessionIndex | Attributes, most values | NameFormat | xsi:type on values | AuthnContextClassRef |
|---|---|---|---|---|---|---|---|---|---|---|
| `simplesamlphp-2.5.3.1-idp-response-to-model-2026-09-30.xml` | transient, 43 characters, SPNameQualifier | -30 s, +300 s | +300 s | +28800 s (AuthnInstant +0 s) | 1 (1) | 43 characters | 2, 2 | uri | xs:string | Password |

| Metadata | Bytes | entityID length | Role, flags | KeyDescriptor | Endpoints | NameIDFormat | Other |
|---|---|---|---|---|---|---|---|
| `simplesamlphp-2.5.3.1-idp-metadata-exchange-2026-09-30.xml` | 4 148 | 61 | IDPSSODescriptor | signing (1 certificate), encryption (1 certificate) | SingleLogoutService HTTP-Redirect, SingleLogoutService HTTP-POST, SingleSignOnService HTTP-Redirect, SingleSignOnService HTTP-POST | transient | IDPSSODescriptor@errorURL |
| `simplesamlphp-2.5.3.1-sp-metadata-for-model-2026-09-30.xml` | 4 384 | 70 | SPSSODescriptor AuthnRequestsSigned="true" | signing (1 certificate), encryption (1 certificate) | SingleLogoutService HTTP-Redirect, SingleLogoutService HTTP-POST, AssertionConsumerService HTTP-POST index 0, AssertionConsumerService HTTP-Artifact index 1 |  | SPSSODescriptor/Extensions |

Against the provisional bounds of section 7 of the specification, nothing beyond section 4: one audience, two
attributes of at most two values, one `SessionIndex`, one signing and one encryption certificate per role, at most
two endpoints of one kind, a bearer window of 300 s, no fractional second. The response SimpleSAMLphp writes for a
service provider it reads from the model's metadata has the shape of its response to its own (section 4): the same
windows, formats and signatures.

`timing.php`, the figure of section 9.6 (from `UnverifiedResponse::of()` on the loaded bytes to `AcceptedAssertion`,
a new replay store each time, 20 runs to warm up, then 500), on an Apple M4 under Docker Desktop, 30 September 2026:

| PHP, OpenSSL | The assertion signed: median, 95th percentile | The response and the assertion signed: median, 95th percentile |
|---|---|---|
| 8.5.10, OpenSSL 3.5.7 | 0.28 ms, 0.48 ms | 0.50 ms, 0.52 ms |
| 8.4.25, OpenSSL 3.5.7 | 0.27 ms, 0.28 ms | 0.50 ms, 0.78 ms |

Thirty times under the provisional 15 ms of section 9.6; the second signature nearly doubles the time, the RSA
verifications weighing most.

### Findings

No document of SimpleSAMLphp in the exchange was refused by the model, and SimpleSAMLphp refused none of the model's:
no rule of the specification had to change for the exchange.

- **F-9. SimpleSAMLphp accepts a logout message whose signature fails, unless `validate.logout` is set.** F-3 holds
  for the logout messages, on both roles: the constructor of `SAML2\Message` swallows a signature that fails its
  digest, the message then reads as unsigned, and `Message::validateMessage()` checks a signature only when
  `validate.logout` is set, when the query string carries one, or when the message kept one it could read. Measured
  with the probes of this section: without `validate.logout`, `for-model` closed its session on a `LogoutResponse`
  whose signature failed, and the identity provider started its logout on such a `LogoutRequest`. The model refuses
  both (M-2, section 6.4 by way of 6.3). The `AuthnRequest` is protected the same way by `validate.authnrequest`,
  which SimpleSAMLphp draws from the `AuthnRequestsSigned="true"` of the service provider's metadata. For
  `beffroi/saml` (section 6.9): the service providers it serves may be SimpleSAMLphp installations that verify nothing
  of its logout messages unless configured to.
- **F-10. SimpleSAMLphp publishes HTTP-Redirect alone where the model posts.** Its identity provider publishes its
  single sign-on and single logout services on HTTP-Redirect only, and its service provider its single logout service
  on HTTP-Redirect (and SOAP with an SQL store); the model's writers sign in the XML, for HTTP-POST, and leave the
  signature over a query string to `saml2-bindings` (section 6.8). The exchange therefore publishes HTTP-POST too, in
  the third configuration and on `for-model`, each accepting what it received there over HTTP-POST. Not a rule of the
  model: the judge of `saml2-bindings` plays the default configuration over HTTP-Redirect. The model's identity
  provider publishes HTTP-Redirect alone, where SimpleSAMLphp's service provider sends first anyway
  (`getEndpointPrioritizedByBinding()` with HTTP-Redirect before HTTP-POST, `modules/saml/src/Auth/Source/SP.php`),
  so that its requests reach the model with a signature over their query string, the path of
  `validateAuthenticatedByBinding()`.
- **F-11. SimpleSAMLphp verifies the model's signatures without `KeyInfo`.** The model's writers wrote no `KeyInfo`
  (`Signing::$certificatePem` was `null`); both parties verified every signature under the key of the model's
  metadata (`Message::checkSign()`, `getPublicKeys('signing')`), as `verify.php` and xmlsec1 did. The hint of D-17 is
  not needed by SimpleSAMLphp.
- **F-12. SimpleSAMLphp reads the model's metadata as it is written.** Signed, the `ds:Signature` the first child of
  the `md:EntityDescriptor`, one prefix per namespace, `WantAuthnRequestsSigned`, `AuthnRequestsSigned` and
  `WantAssertionsSigned` written as `true` or `false`: `SAMLParser` read both, mapped the three flags to its own
  settings, and neither verified nor refused the signature, no certificate being configured for it: SimpleSAMLphp
  trusts a metadata file by its channel, as `readTrusted()` does.
- **F-13. SimpleSAMLphp's service provider takes the model's attribute values without `xsi:type`.** Section 12 of the
  specification omits `xsi:type` on written values until a service provider of the judges refuses their absence:
  `for-model` held `uid` and `eduPersonAffiliation` in its session as the model sent them, under the `basic` name
  format and without an attribute map. SimpleSAMLphp's service provider does not require it.
- **F-14. The transient `NameID` round trip.** SimpleSAMLphp's identity provider honoured the model's `NameIDPolicy`
  (transient, `AllowCreate`), and its `NameID` carries the model's service provider as `SPNameQualifier`, which M-12
  accepts on a transient identifier; `for-model` sent back, in its `LogoutRequest`, the `NameID` the model issued with
  its `SPNameQualifier` and its `Format`, and the `SessionIndex`, which the script compared with what the model
  issued, the check `beffroi/saml` owns (section 6.9).
