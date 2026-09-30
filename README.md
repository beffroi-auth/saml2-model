# beffroi-php/saml2-model

The SAML 2.0 model for PHP: the `samlp:`, `saml:` and `md:` objects of the Web Browser SSO and Single Logout
profiles, read strictly, validated against the rules of the profiles, and written, on the safe DOM, XML Signature
and XML Encryption of [`beffroi-php/xml-security`](https://github.com/beffroi-php/xml-security). It knows no HTTP:
the bindings are [`beffroi-php/saml2-bindings`](https://github.com/beffroi-php/saml2-bindings).

[`spec/model.md`](spec/model.md) is the law of the package: the code conforms to it, or the document changes first.
This file is its short version. Nothing is built yet; the specification is the whole repository until the first
story lands.

## What it guarantees

Each is code, never an option, and has its tests (section 4 of the specification).

| | |
|---|---|
| M-1 | An assertion is read from what `Dsig` verified, never from the document as it arrived. |
| M-2 | Every assertion is covered by a signature, its own or the response's; every signature present verifies. |
| M-3 | A peer's keys come from its metadata; the `KeyInfo` of a message is never read. |
| M-4 | One assertion per response, found as a direct child; one subject, one bearer confirmation, one statement of each kind. |
| M-5 | The order and cardinality of the schema are code; closed vocabularies refuse the unknown. |
| M-6 | One lexical form per value: UTC times with `Z`, four booleans never cast, absolute URIs of 1 024 characters at most. |
| M-7 | Time comes from a PSR-20 clock; every window has a bounded skew. |
| M-8 | `Issuer`, `Audience`, `Recipient` and `Destination` are compared byte for byte with what the consumer states. |
| M-9 | An assertion goes only to an assertion consumer service the service provider's metadata lists. |
| M-10 | `InResponseTo` answers the request the consumer names, or is absent when it accepts an unsolicited response. |
| M-11 | A verified assertion is accepted once, through a replay port. |
| M-12 | A `NameID` follows the rules of its format, read whole, comments and all, never trimmed. |
| M-13 | A failure status, an unknown condition, an unsupported element: each is a refusal. |
| M-14 | One loader and one ID space for SAML, XML Signature and XML Encryption. |
| M-15 | What the package writes, it reads back under the same rules. |
| M-16 | A refusal names its rule and never carries a value of the message. |
| M-17 | Every count and length is bounded. |

## Security

Report privately through the security advisories of this repository. Every fix ships with an advisory and a CVE
(specification, section 10).

## License

MIT.
