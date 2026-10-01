#!/usr/bin/env bash
# Plays, with curl and one cookie jar as a browser would, a login and a logout started by the SimpleSAMLphp service
# provider of http://localhost:8082 against the SimpleSAMLphp identity provider of http://localhost:8081, and keeps
# every SAML document of the exchange in tests/Fixture/real/, byte for byte as decoded:
#   - both metadata, as their URLs serve them;
#   - the AuthnRequest, the LogoutRequest and the LogoutResponse that HTTP-Redirect carries in the query string,
#     URL-decoded, base64-decoded and raw-inflated (SAML Bindings section 3.4.4.1), the XML signature removed by the
#     binding, whose signature over the query string is verified here under the certificate of the sender's metadata;
#   - the response that HTTP-POST carries in a form field, base64-decoded.
# A probe follows: a response whose own signature fails while its assertion's holds, posted to the service provider,
# which answers with what it does of it; nothing of it is kept.
# Then it restarts the identity provider in the second configuration (SSP_SIGN_RESPONSE=false) and plays the login
# again to keep the response whose assertion alone is signed, and restores the default configuration.
# Run from anywhere, with Docker, bash and curl (tests/Interop/simplesamlphp/README.md):
#   bash tests/Interop/simplesamlphp/installation/capture.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
out=$(cd "$here/../../../Fixture/real" && pwd)
version=2.5.3.1
today=$(date -u +%Y-%m-%d)
idp=http://localhost:8081/simplesaml
sp=http://localhost:8082/simplesaml
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

compose() {
    docker compose -f "$here/compose.yaml" "$@"
}

# php <code> [args...]: PHP in the running identity provider container, stdin passed through.
php() {
    local code=$1
    shift
    compose exec -T idp php -r "$code" -- "$@"
}

fixture() {
    printf '%s/simplesamlphp-%s-%s-%s.xml' "$out" "$version" "$1" "$today"
}

# request <method> <url> [curl arguments...]: one hop, never followed; the status, headers and body land in $work.
request() {
    local method=$1 url=$2
    shift 2
    curl -sS -X "$method" -b "$work/cookies" -c "$work/cookies" -D "$work/headers" -o "$work/body" \
        -w '%{http_code}' "$@" "$url" > "$work/status"
}

location() {
    tr -d '\r' < "$work/headers" | sed -n 's/^[Ll]ocation: //p' | tail -1
}

expect_redirect() {
    local status
    status=$(cat "$work/status")
    case $status in
        302 | 303) location ;;
        *)
            echo "expected a redirect from $1, got HTTP $status" >&2
            exit 1
            ;;
    esac
}

query_parameter() {
    printf '%s' "$2" | sed -n "s/.*[?&]$1=\\([^&]*\\).*/\\1/p"
}

html_field() {
    php '$html = stream_get_contents(STDIN);
        if (preg_match("/<input[^>]*name=\"" . $argv[1] . "\"[^>]*value=\"([^\"]*)\"/", $html, $m) === 1) {
            echo html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5);
        }' "$1" < "$work/body"
}

form_action() {
    php '$html = stream_get_contents(STDIN);
        if (preg_match("/<form[^>]*action=\"([^\"]*)\"/", $html, $m) === 1) {
            echo html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5);
        }' < "$work/body"
}

# keep_redirect <URL> <parameter> <fixture> <sender metadata>: the document an HTTP-Redirect URL carries, decoded
# into the work directory, then moved into the fixture once its query string signature is verified under the
# sender's metadata, so that no fixture is ever left whose signature did not verify.
keep_redirect() {
    local url=$1 parameter=$2 file=$3 metadata=$4
    query_parameter "$parameter" "$url" \
        | php '$xml = gzinflate(base64_decode(urldecode(stream_get_contents(STDIN)), true));
            if ($xml === false || $xml === "") { fwrite(STDERR, "not a DEFLATE-encoded message\n"); exit(1); }
            echo $xml;' > "$work/redirect.xml"
    verify_redirect "$url" "$parameter" < "$metadata"
    mv "$work/redirect.xml" "$file"
    echo "kept $(basename "$file") ($(wc -c < "$file" | tr -d ' ') bytes), its query string signature valid"
}

# verify_redirect <URL> <parameter> < metadata: SAML Bindings section 3.4.4.1, the octets signed are
# SAMLRequest or SAMLResponse, RelayState and SigAlg, in that order, as they appear in the URL.
verify_redirect() {
    php '[$url, $parameter] = [$argv[1], $argv[2]];
        $pairs = [];
        foreach (explode("&", (string) parse_url($url, PHP_URL_QUERY)) as $pair) {
            [$name, $value] = explode("=", $pair, 2) + [1 => ""];
            $pairs[$name] = $value;
        }
        if (!isset($pairs["Signature"], $pairs["SigAlg"])) { fwrite(STDERR, "no query string signature\n"); exit(1); }
        $signed = $parameter . "=" . $pairs[$parameter];
        if (isset($pairs["RelayState"])) { $signed .= "&RelayState=" . $pairs["RelayState"]; }
        $signed .= "&SigAlg=" . $pairs["SigAlg"];
        $algorithms = ["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => OPENSSL_ALGO_SHA256];
        $algorithm = $algorithms[urldecode($pairs["SigAlg"])] ?? null;
        if ($algorithm === null) { fwrite(STDERR, "unexpected SigAlg " . urldecode($pairs["SigAlg"]) . "\n"); exit(1); }
        $metadata = new DOMDocument();
        $metadata->loadXML(stream_get_contents(STDIN));
        $certificate = null;
        foreach ($metadata->getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata", "KeyDescriptor") as $key) {
            if (in_array($key->getAttribute("use"), ["", "signing"], true)) {
                $certificate = $key->getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509Certificate")->item(0)->textContent;
                break;
            }
        }
        $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split(preg_replace("/\s+/", "", (string) $certificate), 64, "\n") . "-----END CERTIFICATE-----\n";
        if (openssl_verify($signed, base64_decode(urldecode($pairs["Signature"]), true), $pem, $algorithm) !== 1) {
            fwrite(STDERR, "the query string signature does not verify\n");
            exit(1);
        }' "$1" "$2"
}

wait_until_up() {
    for _ in $(seq 1 30); do
        if curl -fsS -o /dev/null "$idp/module.php/saml/idp/metadata" 2>/dev/null \
            && curl -fsS -o /dev/null "$sp/module.php/saml/sp/metadata/default-sp" 2>/dev/null; then
            return
        fi
        sleep 1
    done
    echo "SimpleSAMLphp did not come up" >&2
    exit 1
}

# authenticate [<fixture of the AuthnRequest>]: the service provider's login, from its login URL to the identity
# provider's HTTP-POST form, whose SAMLResponse, RelayState and action land in $saml_response, $relay_state and
# $acs; keeps the AuthnRequest when an argument names its fixture.
authenticate() {
    local request_file=${1:-} url action auth_state

    request GET "$sp/module.php/saml/sp/login/default-sp?ReturnTo=$sp/module.php/core/welcome"
    url=$(expect_redirect 'the login URL of the service provider')
    case $url in "$idp/module.php/saml/idp/singleSignOnService?"*) ;; *) echo "unexpected $url" >&2; exit 1 ;; esac
    if [ -n "$request_file" ]; then
        keep_redirect "$url" SAMLRequest "$request_file" "$(fixture sp-metadata)"
    fi

    request GET "$url"
    url=$(expect_redirect 'the single sign-on service of the identity provider')
    request GET "$url"
    auth_state=$(html_field AuthState)
    [ -n "$auth_state" ] || { echo "no login form at $url" >&2; exit 1; }
    action=$(form_action)
    case $action in http*) ;; *) action=$url ;; esac
    request POST "$action" --data-urlencode "username=student" --data-urlencode "password=studentpass" \
        --data-urlencode "AuthState=$auth_state"
    while [ "$(cat "$work/status")" = 302 ] || [ "$(cat "$work/status")" = 303 ]; do
        request GET "$(location)"
    done

    saml_response=$(html_field SAMLResponse)
    relay_state=$(html_field RelayState)
    acs=$(form_action)
    [ -n "$saml_response" ] || { echo "no SAMLResponse form after the login" >&2; exit 1; }
}

# login <fixture of the response> [<fixture of the AuthnRequest>]: authenticate, keep the response, post it to the
# assertion consumer service, which must accept it.
login() {
    local response_file=$1 url
    authenticate "${2:-}"
    printf '%s' "$saml_response" \
        | php '$xml = base64_decode(stream_get_contents(STDIN), true);
            if ($xml === false || $xml === "") { fwrite(STDERR, "not base64\n"); exit(1); }
            echo $xml;' > "$response_file"
    echo "kept $(basename "$response_file") ($(wc -c < "$response_file" | tr -d ' ') bytes), posted to $acs"

    request POST "$acs" --data-urlencode "SAMLResponse=$saml_response" --data-urlencode "RelayState=$relay_state"
    url=$(expect_redirect 'the assertion consumer service of the service provider')
    [ "$url" = "$sp/module.php/core/welcome" ] || { echo "the assertion consumer service sent to $url" >&2; exit 1; }
    echo "the service provider accepted the response and returned to $url"
}

# probe: authenticate, move the response's own IssueInstant by one second, outside the assertion, so that the
# response's signature fails its digest while the assertion's holds, post it, and report what the service provider
# answers. Nothing is kept: the finding is the answer (README, finding F-3).
probe() {
    local tampered
    authenticate
    tampered=$(printf '%s' "$saml_response" \
        | php '$xml = base64_decode(stream_get_contents(STDIN), true);
            $xml = preg_replace_callback("/(<samlp:Response [^>]*IssueInstant=\")([^\"]+)(\")/",
                static fn (array $m): string => $m[1] . gmdate("Y-m-d\\TH:i:s\\Z", strtotime($m[2]) + 1) . $m[3], $xml, 1);
            echo base64_encode($xml);')
    [ "$tampered" != "$saml_response" ] || { echo "the probe changed nothing" >&2; exit 1; }
    request POST "$acs" --data-urlencode "SAMLResponse=$tampered" --data-urlencode "RelayState=$relay_state"
    if [ "$(cat "$work/status")" = 303 ] && [ "$(location)" = "$sp/module.php/core/welcome" ]; then
        echo "probe: the service provider ACCEPTED a response whose own signature fails, its assertion's holding"
    else
        echo "probe: the service provider refused it (HTTP $(cat "$work/status"))"
    fi
}

logout() {
    local url
    request GET "$sp/module.php/core/logout/default-sp?ReturnTo=$sp/module.php/core/welcome"
    url=$(expect_redirect 'the logout URL of the service provider')
    case $url in "$idp/module.php/saml/idp/singleLogout?"*) ;; *) echo "unexpected $url" >&2; exit 1 ;; esac
    keep_redirect "$url" SAMLRequest "$(fixture sp-logoutrequest)" "$(fixture sp-metadata)"

    request GET "$url"
    url=$(expect_redirect 'the single logout service of the identity provider')
    while case $url in "$idp/"*) true ;; *) false ;; esac; do
        request GET "$url"
        url=$(expect_redirect "$url")
    done
    case $url in "$sp/module.php/saml/sp/saml2-logout.php/default-sp?"*) ;; *) echo "unexpected $url" >&2; exit 1 ;; esac
    if [ -n "$(query_parameter Signature "$url")" ]; then
        keep_redirect "$url" SAMLResponse "$(fixture idp-logoutresponse)" "$(fixture idp-metadata)"
    else
        query_parameter SAMLResponse "$url" \
            | php 'echo gzinflate(base64_decode(urldecode(stream_get_contents(STDIN)), true));' > "$(fixture idp-logoutresponse)"
        echo "kept $(basename "$(fixture idp-logoutresponse)"), without query string signature"
    fi

    request GET "$url"
    url=$(expect_redirect 'the single logout service of the service provider')
    echo "the service provider closed its session and returned to $url"
}

echo "== default configuration: SimpleSAMLphp $version as it ships, the response and the assertion signed"
# The directory of the exchange's metadata, mounted by compose.yaml: created here, so that Docker does not, as root.
mkdir -p "$here/../written"
compose up -d --build --force-recreate
wait_until_up
curl -fsS -o "$(fixture idp-metadata)" "$idp/module.php/saml/idp/metadata"
curl -fsS -o "$(fixture sp-metadata)" "$sp/module.php/saml/sp/metadata/default-sp"
echo "kept $(basename "$(fixture idp-metadata)") and $(basename "$(fixture sp-metadata)")"
: > "$work/cookies"
login "$(fixture idp-response-signed-both)" "$(fixture sp-authnrequest)"
logout
: > "$work/cookies"
probe

echo "== second configuration: saml20.sign.response false, the assertion alone signed"
SSP_SIGN_RESPONSE=false compose up -d --force-recreate idp
wait_until_up
: > "$work/cookies"
login "$(fixture idp-response-signed-assertion)"

echo "== default configuration restored"
compose up -d --force-recreate idp
wait_until_up
