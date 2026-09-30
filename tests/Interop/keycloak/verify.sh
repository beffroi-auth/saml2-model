#!/bin/sh
# Verifies with xmlsec1, the implementation that is neither Keycloak nor this package (spec/model.md section 9.4,
# xml-security's spec/dsig.md section 9.1), every signature of every Keycloak document captured into the directory
# given, under the certificate of its producer's metadata captured with it: keycloak-<version>-<idp|sp>-<document>-<date>.xml
# is verified with the signing certificate of keycloak-<version>-<idp|sp>-metadata-<date>.xml. The SAML ID attributes
# are declared to xmlsec1; each ds:Signature child of the root and of a direct saml:Assertion child is verified on its
# own. Two controls per signature must fail: the same check under a throwaway key, which proves the key comes from the
# metadata and not from the KeyInfo of the message, and the check of a copy whose signed IssueInstant (entityID for
# metadata) is altered. Run from the root of the repository in Alpine 3.22:
#   docker run --rm -v "$PWD:/project:ro" -w /project alpine:3.22 sh -c \
#       'apk add -q xmlsec libxml2-utils openssl >/dev/null && sh tests/Interop/keycloak/verify.sh tests/Fixture/real'
set -eu

directory=$1
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=throwaway -days 1 -keyout "$work/throwaway-key.pem" \
    -out "$work/throwaway.pem" 2>/dev/null

verify() {
    xmlsec1 --verify --lax-key-search --pubkey-cert-pem "$1" \
        --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response \
        --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:AuthnRequest \
        --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:LogoutRequest \
        --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:LogoutResponse \
        --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion \
        --id-attr:ID urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor \
        --node-xpath "$2" "$3" >"$work/xmlsec.log" 2>&1
}

signatures=0
failures=0
for file in "$directory"/keycloak-*.xml; do
    [ -f "$file" ] || continue
    base=$(basename "$file" .xml)
    metadata=$directory/$(printf '%s' "$base" | sed 's/^\(keycloak-[0-9.]*-[a-z]*\)-.*-\([0-9-]\{10\}\)$/\1-metadata-\2/').xml
    found=0
    for xpath in '/*/*[local-name()="Signature"]' '/*/*[local-name()="Assertion"]/*[local-name()="Signature"]'; do
        [ "$(xmllint --xpath "count($xpath)" "$file")" = 1 ] || continue
        found=1
        signatures=$((signatures + 1))
        certificate=$(xmllint --xpath 'string((/*/*/*[local-name()="KeyDescriptor"][not(@use) or @use="signing"]//*[local-name()="X509Certificate"])[1])' "$metadata" 2>/dev/null || true)
        if [ -z "$certificate" ]; then
            echo "FAIL $base $xpath: no signing certificate in $(basename "$metadata")"
            failures=$((failures + 1))
            continue
        fi
        { echo '-----BEGIN CERTIFICATE-----'; printf '%s' "$certificate" | tr -d ' \n\r\t' | fold -w 64; echo; echo '-----END CERTIFICATE-----'; } >"$work/certificate.pem"
        case $xpath in
            *Assertion*) sed 's/\(<[A-Za-z]*:\{0,1\}Assertion [^>]*IssueInstant="\)2/\19/' "$file" >"$work/altered.xml" ;;
            *) sed -e '1s/IssueInstant="2/IssueInstant="9/' -e '1s/entityID="/entityID="x/' "$file" >"$work/altered.xml" ;;
        esac
        if ! verify "$work/certificate.pem" "$xpath" "$file"; then
            echo "FAIL $base $xpath: $(tail -n 1 "$work/xmlsec.log")"
            failures=$((failures + 1))
        elif verify "$work/throwaway.pem" "$xpath" "$file"; then
            echo "FAIL $base $xpath: verified under a throwaway key"
            failures=$((failures + 1))
        elif cmp -s "$file" "$work/altered.xml" || verify "$work/certificate.pem" "$xpath" "$work/altered.xml"; then
            echo "FAIL $base $xpath: an altered copy verified"
            failures=$((failures + 1))
        else
            echo "OK   $base $xpath: verified under $(basename "$metadata"); throwaway key and altered copy refused"
        fi
    done
    [ "$found" = 1 ] || echo "--   $base: no signature"
done
echo "$signatures signatures, $failures failures."
[ "$signatures" -gt 0 ] && [ "$failures" = 0 ]
