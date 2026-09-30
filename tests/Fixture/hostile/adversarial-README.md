# Adversarial fixtures

The `adversarial-*` files of this directory and of `../behaviour/` are the attempts of the adversarial pass of section
9.8 of `spec/model.md` (story #12): each row of section 3 attacked with inputs the corpus of 9.2 and 9.3 does not list,
every attempt a file whatever its outcome, `adversarial-<attempt>-refused.xml` here and
`adversarial-<attempt>-accepted.xml` in `../behaviour/`. `tests/Unit/AdversarialTest.php` asserts each, refused with the
exception and the message it got, or accepted with the values read, and fails when an attempt of the builder is asserted
by no case.

They are written by `tests/Support/AdversarialFixtureBuilder.php`, never by hand, each a variant of one valid message
with the change its name says, signed with the test keys of `../keys/` through `Beffroi\Xml\Dsig\Signer` wherever the
attack needs a valid signature. From the root of the repository, after `castor install`:

```
docker run --rm -v "$PWD:/project" -w /project ghcr.io/spomky-labs/phpqa:8.5 \
    php -r 'require "vendor/autoload.php"; Beffroi\Saml2\Model\Tests\Support\AdversarialFixtureBuilder::write("tests/Fixture");'
```

RSA PKCS#1 v1.5 signatures are deterministic, so the command writes the committed bytes again, and the adversarial test
compares what the builder writes with every committed file. Run on 30 September 2026 in the phpqa image, PHP 8.5.10.

Every message is issued at `2026-09-30T11:59:59Z` and the tests freeze the clock at `12:00:00Z`: the response of the
identity provider `https://idp.example.com/saml` answers the request `_request` of the service provider
`https://sp.example.com/saml` at `https://sp.example.com/saml/acs`; the AuthnRequest `_authn-request` goes the other way,
to `https://idp.example.com/saml/sso`; the LogoutRequest `_logout-request` goes from the identity provider to
`https://sp.example.com/saml/slo`, and the LogoutResponse `_logout-response` back to `https://idp.example.com/saml/slo`.
A file is written as the serializer writes it, unless the attack lies in bytes the serializer would write otherwise (a
character reference, a node inserted after signing) or the loader refuses it: those are written as built, the XML
declaration in front.

| Group | Attempts | Refused | Accepted |
|---|---|---|---|
| Wrapping: the signed assertion in `samlp:Status`, `samlp:StatusCode`, `samlp:StatusMessage`, `samlp:StatusDetail`, `saml:SubjectConfirmationData`, `saml:Conditions`, `saml:Attribute`, `saml:AttributeValue`, `samlp:Extensions` under another prefix or the default namespace, the response's `saml:Issuer`; its signature copied, the response signed; an unsigned assertion next to the signed one or in its `ds:KeyInfo` | 18 | 15 | 3 |
| Namespaces and prefixes: the default namespace, another prefix, the two prefixes swapped, every namespace declared again, a prefix rebound on a child, a SAML name in the SAML 1.0, an upper-case or no namespace, attributes in a namespace next to the real ones | 18 | 11 | 7 |
| `xml:base` and `xml:lang` on every element of each message, and a relative URI an `xml:base` would resolve | 12 | 6 | 6 |
| IDs that differ by case, Unicode composition, a full-width character or a space, an `xml:id`, for the wrapped signature, `InResponseTo`, the replay pair and the one ID space | 15 | 10 | 5 |
| Times at the edges of their lexical form, nine and ten fractional digits, a bound missed by less than a microsecond | 25 | 20 | 5 |
| Booleans at the edges of their four forms | 15 | 12 | 3 |
| URIs that differ by what a normaliser would erase: scheme and host case, a default or empty port, a trailing dot, dot segments, percent-encoding, user information, an empty query or fragment, a homograph host, a zero-width space | 30 | 30 | 0 |
| Bounds of section 7 at and one over their value, in characters of one byte and of two | 27 | 8 | 19 |
| Comments and processing instructions after and before signing, a CDATA section, a character reference | 13 | 5 | 8 |
| The other rows: key substitution, a signature out of its place, replay in another response, a condition of another namespace, the vocabularies in another case | 17 | 15 | 2 |
| **Written by the builder** | **190** | **132** | **58** |

The pass accepted the `NameID` holding a right-to-left override, which M-6 and M-12 refuse since story #13: the builder
writes it here, `adversarial-response-name-id-with-a-right-to-left-override-refused.xml`, the same bytes under the
name of its outcome.

Seven more are written by hand with the fixes they pin, each a valid document of `../behaviour/` with one change, and
asserted by the test of the class the fix touched; the three that found the bypass of the Issuer qualifiers are attempts
of the pass, and the adversarial test asserts them too:

| File | Made from | Asserted by |
|---|---|---|
| `adversarial-metadata-identity-provider-valid-until-passed-refused.xml`, `../behaviour/adversarial-metadata-role-valid-until-accepted.xml` | `metadata-identity-provider.xml`, a `validUntil` on its role | `tests/Unit/Metadata/MetadataReaderTest.php`, section 6.5 step 4 |
| `adversarial-metadata-service-provider-valid-until-passed-refused.xml` | `metadata-service-provider.xml`, a `validUntil` on its role | the same |
| `../behaviour/adversarial-metadata-ignored-roles-valid-until-passed-accepted.xml` | `metadata-identity-provider.xml`, a SAML 1.1 role and an attribute authority past their `validUntil` | the same |
| `adversarial-authn-request-issuer-name-qualifier-refused.xml` | `authn-request-unsigned.xml`, a `NameQualifier` on its Issuer | `tests/Unit/Validation/AuthnRequestValidatorTest.php` and `tests/Unit/AdversarialTest.php`, M-8 |
| `adversarial-logout-request-issuer-sp-name-qualifier-refused.xml` | `logout-request-written-for-http-redirect.xml`, an `SPNameQualifier` on its Issuer | `tests/Unit/Validation/LogoutRequestValidatorTest.php` and `tests/Unit/AdversarialTest.php`, M-8 |
| `adversarial-logout-response-issuer-sp-provided-id-refused.xml` | `logout-response-written-for-http-redirect.xml`, an `SPProvidedID` on its Issuer | `tests/Unit/Validation/LogoutResponseValidatorTest.php` and `tests/Unit/AdversarialTest.php`, M-8 |
