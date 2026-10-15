# beffroi/saml2-model

Part of [beffroi/framework](https://github.com/beffroi-php/beffroi), developed in `src/saml2-model` of that monorepo; this repository is its
read-only split. Issues and pull requests go to the monorepo.

The SAML 2.0 model for PHP: the `samlp:`, `saml:` and `md:` objects of the Web Browser SSO and Single Logout
profiles, read strictly, validated against the rules of the profiles in code rather than in options, and written, on
the safe DOM and the XML Signature of [`beffroi/xml-security`](https://github.com/beffroi-php/xml-security). It
reads an assertion only in what a signature covers, takes a peer's keys from its metadata only, and knows no HTTP:
the bindings are [`beffroi/saml2-bindings`](https://github.com/beffroi-php/saml2-bindings).

[`spec/model.md`](spec/model.md) is the law of the package: the code conforms to it, or the document changes first.
This file is its short version.

The package requires PHP 8.4 or later, `beffroi/xml-security` and `psr/clock`, and nothing else. Neither has a
tag yet: both are required at the maintenance branch.

```json
{
    "require": {"beffroi/saml2-model": "0.0.x-dev"},
    "minimum-stability": "dev",
    "prefer-stable": true
}
```

## Reading a response, service provider side

```php
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\{ExpectedResponse, ResponseValidator, TimeBounds};

$loader = SamlLoader::create();                        // one loader, one ID space for SAML, ds: and xenc: (M-14)
$response = UnverifiedResponse::of($loader->load($bytes));   // the bytes a binding decoded
// $response->issuer and $response->inResponseTo choose the peer, and nothing else (M-1)
$idp = $peers->identityProvider($response->issuer);   // your store of the metadata you read with MetadataReader

$accepted = new ResponseValidator($loader, $clock, $replayGuard, new TimeBounds())->validate(
    $response,
    $idp,
    ExpectedResponse::toRequest($requestId, 'https://sp.example.com/saml/acs', 'https://sp.example.com/saml'),
);
$accepted->assertion->nameId->value;                   // read from the verified document only
$accepted->assertion->attributes;                      // in document order, never merged
$accepted->coverage;                                   // SignatureCoverage::Assertion, Response or AssertionAndResponse
```

`validate()` refuses with a `MessageRefused` naming its rule, `SignatureRequired`, `AudienceMismatch`,
`OutsideValidityWindow`, `Replayed` and the others of section 5.8, and lets the refusals of `Core` and `Dsig`
through as they are. `ExpectedResponse::unsolicited()` accepts a response to no request, when your policy does.

## Validating a request and writing a response, identity provider side

```php
use Beffroi\Saml2\Model\Assertion\{Assertion, AuthnStatement, Conditions, Issuer, NameId, NameIdFormat, SubjectConfirmation};
use Beffroi\Saml2\Model\Protocol\{Response, Status, StatusCode, UnverifiedAuthnRequest};
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Saml2\Model\Writing\{ResponseWriter, SignedParts, Signing};
use Beffroi\Xml\Dsig\PrivateKey;

$request = UnverifiedAuthnRequest::of(SamlLoader::create()->load($bytes));
$accepted = new AuthnRequestValidator(SamlLoader::create(), $clock)
    ->validate($request, $sp, $self, 'https://idp.example.com/saml/sso');   // HTTP-POST, or HTTP-Redirect unsigned
// ->validateAuthenticatedByBinding(...) when saml2-bindings verified the signature of the query string
$acs = $accepted->assertionConsumerService;           // from the service provider's metadata, never the request (M-9)

$now = $clock->now();
$assertion = new Assertion(
    SamlId::generate(),
    $now,
    new Issuer('https://idp.example.com/saml'),
    new NameId('_7a2f4c1d9e', NameIdFormat::Persistent),
    new SubjectConfirmation($acs->location, $now->modify('+5 minutes'), $accepted->request->id, null),
    new Conditions($now, $now->modify('+5 minutes'), [[$sp->entityId]], false),
    new AuthnStatement($now, '_session', null, 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'),
    [],
);
$document = new ResponseWriter()->write(
    new Response(SamlId::generate(), $now, new Issuer('https://idp.example.com/saml'), $acs->location,
        $accepted->request->id, new Status(StatusCode::Success), $assertion),
    new Signing(PrivateKey::fromPem($keyPem)),        // or any Dsig SigningKeyInterface, a key management service's
    SignedParts::Assertion,                            // or AssertionAndResponse
);
```

The writer checks what the peer's validator would refuse before it builds anything, builds with one prefix per
namespace, signs through `Dsig`'s `Signer`, and returns a `Document`: serializing it is `Core`'s `Serializer`, called
by the binding. `writeFailure()` writes a response whose status is not `Success`. `AuthnRequestWriter`,
`LogoutRequestWriter` and `LogoutResponseWriter` write the other messages, signed for HTTP-POST, unsigned for
HTTP-Redirect, whose binding signs the query string; `LogoutRequestValidator` and `LogoutResponseValidator` read them,
with the same two methods as `AuthnRequestValidator`, and take the replay port as `ResponseValidator` does: a logout
message they accepted is `Replayed` when it comes again inside its window (M-11).

## Reading and writing metadata

```php
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Writing\MetadataWriter;

$reader = new MetadataReader(SamlLoader::create(), $clock);
$descriptor = $reader->readTrusted($document);          // trusted by its channel: an upload, a pinned URL over TLS
$descriptor = $reader->readSigned($document, $keys);    // its signature verified with keys you pinned
$descriptor->identityProvider?->verificationKeys();     // the Dsig keys of its signing certificates, or null

$document = new MetadataWriter()->write($descriptor, new Signing($key));   // or null, unsigned
```

Endpoints on other bindings than HTTP-Redirect and HTTP-POST are dropped, other role descriptors skipped, so that a
real metadata loads; what the profiles need and the package does not support, `md:EntitiesDescriptor` or a bare
`ds:KeyValue`, is refused by name.

## The two ports

The clock is PSR-20's `Psr\Clock\ClockInterface`, read once per validation. The replay port is one method you
implement over a store every worker of your deployment shares, atomically:

```php
namespace Beffroi\Saml2\Model\Port;

interface ReplayGuardInterface
{
    /** true when the pair was new and is now remembered until $expiresAt, false when it was seen */
    public function remember(string $issuer, string $id, \DateTimeImmutable $expiresAt): bool;
}
```

The in-memory doubles of both ports live in `tests/saml2-model/Support/` of the monorepo and are not shipped: a per-process store in a pool of
workers forgets across workers.

## The invariants

Each is code, never an option, and has its tests; `TraceabilityTest` fails when one is cited by no test.

| | |
|---|---|
| M-1 | An assertion is read from what `Dsig` verified, never from the document as it arrived. |
| M-2 | Every assertion is covered by a signature, its own or the response's; every signature a message carries as a direct child verifies. |
| M-3 | A peer's keys come from its metadata; the `KeyInfo` of a message is never read. |
| M-4 | One assertion per response, found as a direct child; one subject, one bearer confirmation, one statement of each kind. |
| M-5 | The order and cardinality of the schema are code; closed vocabularies refuse the unknown. |
| M-6 | One lexical form per value: UTC times with `Z`, four booleans never cast, absolute URIs of 1 024 characters at most, no invisible or reordering character. |
| M-7 | Time comes from a PSR-20 clock; every window has a bounded skew, the age of a message and of an assertion included. |
| M-8 | `Issuer`, `Audience`, `Recipient` and `Destination` are compared byte for byte with what the consumer states. |
| M-9 | An assertion goes only to an assertion consumer service the service provider's metadata lists. |
| M-10 | `InResponseTo` answers the request the consumer names, or is absent when it accepts an unsolicited response. |
| M-11 | A verified assertion, and an accepted logout message, is accepted once, through the replay port. |
| M-12 | A `NameID` follows the rules of its format, read whole, comments and all, never trimmed. |
| M-13 | A failure status, an unknown condition, an unsupported element: each is a refusal. |
| M-14 | One loader and one ID space for SAML, XML Signature and XML Encryption. |
| M-15 | What the package writes, it reads back under the same rules, the counts of its bounds included. |
| M-16 | A refusal names its rule and never carries a value of the message. |
| M-17 | Every count and length is bounded, and checked before anything iterates. |

## What consumers never call

The package reaches the DOM through `xml-security`'s `Core` only and calls nothing its section 8 bans; its own
PHPStan rules, which consumers are asked to copy (`.ci-tools/phpstan-saml2-model.neon`, `tests/saml2-model/PhpStan/`), add every reading of
the machine's clock (`time()`, `date()`, `new \DateTimeImmutable()` without a full date in UTC), every source of
randomness but `random_bytes()`, every `openssl_*` function, the casts to `bool` and the loose comparisons `==`,
`!=` and `switch`. `textContent`, `nodeValue` and `innerHTML` are not read: `Text::of()` is the way, and
`SourceGuardTest` scans `src/` for them. Nothing under `Beffroi\Saml2\Model\Internal\` is part of the compatibility
promise.

## Development

From the root of the monorepo, which holds the toolchain of every package:

```bash
composer install
castor phpunit -- --testsuite saml2-model     # PHPUnit 13 with coverage, this package's suite
castor prepare-pr                             # Mago lint and format, Rector, PHPStan, Deptrac
castor phpstan                                # this package under .ci-tools/phpstan-saml2-model.neon: level max, no baseline, the bans of section 8
castor infect --strict                        # Infection on the files of section 9, no escaped mutant allowed
castor infect --diff                          # the lines changed since origin/HEAD; without either, the whole source
castor saml2-model-xmlsec <file>              # xmlsec1, in Alpine, verifies a signed file; --certificate for the service provider's key
castor saml2-model-oracle                     # every signature the writers make and commit, verified by xmlsec1
castor saml2-model-simplesamlphp              # the judge of section 9.5: SimpleSAMLphp as identity provider and service provider, both ways
castor saml2-model-keycloak                   # Keycloak as identity provider and broker, both ways, by hand
```

Every task runs inside the `ghcr.io/spomky-labs/phpqa` image when Docker is available. The CI runs this package's
suite on PHP 8.5 and on PHP 8.4.

## Security

See the [security policy](https://github.com/beffroi-php/beffroi/blob/0.0.x/SECURITY.md) of the monorepo: private reporting, an advisory and a CVE for
every fix.

## License

MIT, see the [LICENSE](https://github.com/beffroi-php/beffroi/blob/0.0.x/LICENSE) of the monorepo.
