# The xmlsec1 oracle of the writers

xmlsec1, the implementation that is not this one, verifies what the writers sign (section 9.1 of `spec/model.md`,
dsig.md section 9.1). `verify-signatures.sh` verifies every signature of each file it is given, the `ds:Signature`
child of the root and the one of its `saml:Assertion` child, whichever the file carries, under the certificate it is
given, and fails on a file that carries neither.

`tests/Unit/Writing/ResponseWriterOracleTest.php` writes, into the directory `XMLSEC_ORACLE` names, a response signed
with every scheme the build offers, its assertion alone and the response over it, and a signed failure. A PSS
signature is random, so nothing here is pinned: the documents are written again on every run. The job Oracle of the CI
signs in the phpqa image of PHP 8.5 and verifies in Alpine 3.22 (xmlsec1 1.3.7, OpenSSL), with the documents the
writers committed under `tests/Fixture/behaviour/response-written-*.xml`. On the developer's machine:

```
PHP_VERSION=8.5 castor xmlsec-oracle   # writes into tmp-phpqa/oracle, which git ignores, then verifies each
castor xmlsec <file>                   # one file, under the identity provider's test certificate
castor xmlsec <file> --certificate=tests/Fixture/keys/sp-signing-certificate.pem
```

Each runs, in `alpine:3.22` with `apk add xmlsec libxml2-utils`, for each signature the file carries:

```
xmlsec1 --verify --lax-key-search --pubkey-cert-pem <certificate> \
    --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion \
    --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response \
    --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:AuthnRequest \
    --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:LogoutRequest \
    --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:LogoutResponse \
    --id-attr:ID urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor \
    --node-xpath '/*/*[namespace-uri()="http://www.w3.org/2000/09/xmldsig#" and local-name()="Signature"]' <file>
```

and the same with `--node-xpath` naming the `ds:Signature` of the `saml:Assertion` child of the root.
