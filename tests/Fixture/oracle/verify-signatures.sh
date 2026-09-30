#!/bin/sh
# Verifies with xmlsec1, the implementation that is not this one (spec/model.md section 9.1), every signature of each
# file given: the ds:Signature child of the root, and the one of the saml:Assertion child of the root, whichever the
# file carries, under the certificate given. A file without either is an error. Run from the root of the repository,
# where xmlsec1 and xmllint are installed (Alpine 3.22: apk add xmlsec libxml2-utils):
#   sh tests/Fixture/oracle/verify-signatures.sh tests/Fixture/keys/idp-signing-certificate.pem <file>...
set -eu

certificate=$1
shift
dsig='namespace-uri()="http://www.w3.org/2000/09/xmldsig#" and local-name()="Signature"'
assertion='namespace-uri()="urn:oasis:names:tc:SAML:2.0:assertion" and local-name()="Assertion"'
files=0
for file in "$@"; do
    if [ ! -f "$file" ]; then
        echo "No file $file." >&2
        exit 1
    fi
    verified=0
    for signature in "/*/*[$dsig]" "/*/*[$assertion]/*[$dsig]"; do
        if [ "$(xmllint --xpath "count($signature)" "$file")" -eq 0 ]; then
            continue
        fi
        xmlsec1 --verify --lax-key-search --pubkey-cert-pem "$certificate" \
            --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion \
            --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response \
            --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:AuthnRequest \
            --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:LogoutRequest \
            --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:LogoutResponse \
            --id-attr:ID urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor \
            --node-xpath "$signature" "$file"
        verified=$((verified + 1))
    done
    if [ "$verified" -eq 0 ]; then
        echo "$file carries no signature to verify." >&2
        exit 1
    fi
    echo "$file: $verified signatures verified by xmlsec1."
    files=$((files + 1))
done
if [ "$files" -eq 0 ]; then
    echo "No file to verify." >&2
    exit 1
fi
