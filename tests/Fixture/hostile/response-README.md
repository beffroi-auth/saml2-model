# Response fixtures

The `response-*` files of this directory and of `../behaviour/` are the responses of story #7: the message-level
wrapping corpus of section 9.2 of `spec/model.md`, the envelope and status rows around it, and the rows of 9.3 that
concern a response. Each is a variant of one valid response with the one change its name says, signed with the test
keys of `../keys/` through `Beffroi\Xml\Dsig\Signer` wherever the attack needs a valid signature.

They are written by `tests/Support/ResponseFixtureBuilder.php`, never by hand. From the root of the repository, after
`castor install`:

```
docker run --rm -v "$PWD:/project" -w /project ghcr.io/spomky-labs/phpqa:8.5 \
    php -r 'require "vendor/autoload.php"; Beffroi\Saml2\Model\Tests\Support\ResponseFixtureBuilder::write("tests/Fixture");'
```

RSA PKCS#1 v1.5 signatures are deterministic, so the command writes the committed bytes again: the test of the builder,
`tests/Unit/Support/ResponseFixtureBuilderTest.php`, compares what it builds with every committed file and fails on
the first difference.

The valid response answers the request `_request` of the service provider `https://sp.example.com/saml` at its
assertion consumer service `https://sp.example.com/saml/acs`, from the identity provider `https://idp.example.com/saml`,
issued at `2026-09-30T11:59:59Z`, its assertion a second earlier; the tests freeze the clock at `2026-09-30T12:00:00Z`.

Two fixtures are not made by `Signer` alone:

- `response-assertion-in-extensions-same-id-refused.xml` is refused by the loader (`DuplicateId`), so it is written as
  built, the XML declaration in front, never loaded.
- `../behaviour/response-signed-both-prefix-list-accepted.xml` carries an assertion signed with an `InclusiveNamespaces`
  naming the prefix `xs`, which the response declares and uses only in an `xsi:type` value. `Signer` writes no prefix
  list (dsig.md section 6.2 step 5): the builder adds it to the exclusive transform, computes the digest over the
  assertion where it stands with `Core`'s `Canonicalizer`, signs `SignedInfo` again with the test key, then signs the
  response over it.
