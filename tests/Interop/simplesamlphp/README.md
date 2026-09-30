# SimpleSAMLphp, both ways

The judge of sub-spike 9b for this package (section 9.5 of `spec/model.md`), in two halves, reproducible from a clean
checkout and never a dependency of the package: nothing here is in the root `composer.json`, and no CI job runs it
(section 12). Each half is run by hand, from the root of the repository, with Docker; what it produced is committed
under `tests/Fixture/real/` (section 9.4), named with its origin, its version and its date, bytes as written or as
decoded, disposable identities only.

| | |
|---|---|
| `library/` | a throwaway Composer project running `simplesamlphp/saml2`, SimpleSAMLphp's SAML 2 library, in a container: `produce.php` writes the fixtures with the test keys, `verify.php` validates what a producer wrote |
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
