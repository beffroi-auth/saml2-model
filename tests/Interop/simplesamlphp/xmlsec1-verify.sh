#!/bin/sh
# Verifies with xmlsec1, the implementation independent of SimpleSAMLphp and of the model (spec/dsig.md section 9.1
# of xml-security), every XML signature of the documents of a directory that match a glob, each under the
# certificate of the metadata of its signer, taken from the md:EntityDescriptor documents of the same batch:
# a message is verified under the metadata whose entityID is its Issuer, an assertion under the metadata of its own
# Issuer, a signed metadata document under its own certificate. A document holding two signatures, a response
# signed over its signed assertion, has both verified. A document without an XML signature is listed and skipped:
# HTTP-Redirect removes the signature from the XML and signs the query string (SAML Bindings section 3.4.4.1).
# Run in Alpine 3.22 from the root of the repository (tests/Interop/simplesamlphp/README.md):
#   docker run --rm -v "$PWD:/project:ro" -w /project alpine:3.22 sh -c 'apk add -q xmlsec libxml2-utils \
#       && sh tests/Interop/simplesamlphp/xmlsec1-verify.sh tests/Fixture/real "simplesamlphp-saml2-4.20.3-*.xml"'
set -eu

directory=$1
pattern=${2:-*.xml}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

xpath() {
    xmllint --xpath "$1" "$2" 2>/dev/null || true
}

# The certificate of each metadata of the batch, as PEM, named by the SHA-256 of its entityID.
for file in "$directory"/$pattern; do
    [ -f "$file" ] || continue
    [ "$(xpath 'local-name(/*)' "$file")" = EntityDescriptor ] || continue
    entity=$(xpath 'string(/*/@entityID)' "$file")
    certificate=$(xpath 'string((/*/*[local-name()="IDPSSODescriptor" or local-name()="SPSSODescriptor"]/*[local-name()="KeyDescriptor"][not(@use) or @use="signing"]//*[local-name()="X509Certificate"])[1])' "$file" | tr -d ' \t\r\n')
    [ -n "$certificate" ] || continue
    pem="$work/$(printf '%s' "$entity" | sha256sum | cut -c1-64).pem"
    {
        echo '-----BEGIN CERTIFICATE-----'
        printf '%s' "$certificate" | fold -w 64
        echo
        echo '-----END CERTIFICATE-----'
    } > "$pem"
done

verified=0
failed=0
for file in "$directory"/$pattern; do
    [ -f "$file" ] || continue
    name=$(basename "$file")
    signed=0
    for element in '/*' '/*/*[local-name()="Assertion"]'; do
        [ "$(xpath "count($element/*[local-name()=\"Signature\"])" "$file")" = 1 ] || continue
        signed=$((signed + 1))
        if [ "$(xpath 'local-name(/*)' "$file")" = EntityDescriptor ]; then
            signer=$(xpath 'string(/*/@entityID)' "$file")
        else
            signer=$(xpath "string($element/*[local-name()=\"Issuer\"])" "$file")
            [ -n "$signer" ] || signer=$(xpath 'string(/*/*[local-name()="Assertion"]/*[local-name()="Issuer"])' "$file")
        fi
        pem="$work/$(printf '%s' "$signer" | sha256sum | cut -c1-64).pem"
        what="$(xpath "local-name($element)" "$file") signature"
        if [ ! -f "$pem" ]; then
            echo "FAIL $name: $what, no metadata in the batch for $signer"
            failed=$((failed + 1))
            continue
        fi
        if output=$(xmlsec1 --verify --lax-key-search --pubkey-cert-pem "$pem" \
            --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion \
            --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response \
            --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:AuthnRequest \
            --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:LogoutRequest \
            --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:LogoutResponse \
            --id-attr:ID urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor \
            --node-xpath "$element/*[local-name()=\"Signature\"]" "$file" 2>&1); then
            echo "OK   $name: $what verified under the metadata of $signer"
            verified=$((verified + 1))
        else
            echo "FAIL $name: $what: $(printf '%s' "$output" | tr '\n' ' ')"
            failed=$((failed + 1))
        fi
    done
    [ "$signed" -gt 0 ] || echo "SKIP $name: no XML signature"
done
echo "$verified signatures verified by $(xmlsec1 --version), $failed failed"
[ "$failed" -eq 0 ] && [ "$verified" -gt 0 ]
