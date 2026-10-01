#!/usr/bin/env bash
# Plays a login and a logout through the broker of realm sp against realm idp of the Keycloak of compose.yaml, with
# curl and one cookie jar, and keeps every SAML document on the way (spec/model.md, sections 9.4 and 9.5; story #14):
# both metadata as served, the documents HTTP-Redirect carries URL-decoded, base64-decoded and raw-inflated, the ones
# HTTP-POST carries base64-decoded, each written byte for byte as decoded, never reformatted. Run from anywhere once
# `docker compose up -d` has imported the realms:
#   bash tests/Interop/keycloak/capture.sh [output directory, default tests/Fixture/real]
# Needs bash 3.2 or later, curl and perl with its core modules (MIME::Base64, Compress::Raw::Zlib, JSON::PP).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out=${1:-$root/tests/Fixture/real}
base=http://localhost:8180
client_redirect=$base/capture
# The disposable test user of realms/idp.json.
username=alice
password=alice

version=$(sed -n 's|.*image: quay.io/keycloak/keycloak:\([0-9.]*\).*|\1|p' "$here/compose.yaml")
[ -n "$version" ] || { echo 'No Keycloak version in compose.yaml.' >&2; exit 1; }
day=$(date -u +%Y-%m-%d)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
jar=$work/cookies
step=0

fail() { echo "capture: $*" >&2; exit 1; }
name() { printf '%s/keycloak-%s-%s-%s-%s.xml' "$out" "$version" "$1" "$2" "$day"; }

# request METHOD URL [curl arguments...]: one exchange, headers in $work/N.h, body in $work/N.b, $step set to N.
request() {
    local method=$1 url=$2
    shift 2
    step=$((step + 1))
    curl -sS -X "$method" -b "$jar" -c "$jar" -D "$work/$step.h" -o "$work/$step.b" "$@" "$url"
}
status() { sed -n '1s/^HTTP\/[0-9.]* \([0-9]*\).*/\1/p' "$work/$step.h"; }
location() { tr -d '\r' < "$work/$step.h" | sed -n 's/^[Ll]ocation: //p'; }

# query_param NAME < URL: the value of a query parameter, URL-decoded.
query_param() {
    perl -e 'local $/; my $u = <STDIN>; my $n = shift; $u =~ /[?&]\Q$n\E=([^&#]*)/ or exit 1;
        my $v = $1; $v =~ tr/+/ /; $v =~ s/%([0-9A-Fa-f]{2})/chr hex $1/ge; print $v' "$1"
}
# query_names < URL: the names of the query parameters, in order.
query_names() { perl -e 'local $/; my $u = <STDIN>; $u =~ s/^[^?]*\?//; print join(" ", map { (split /=/)[0] } split /&/, $u), "\n"'; }
# form_field NAME < HTML: the value of a hidden input of an HTML form, its character references resolved.
form_field() {
    perl -e 'local $/; my $h = <STDIN>; my $n = shift; $h =~ /<input[^>]*name="\Q$n\E"[^>]*value="([^"]*)"/i or exit 1;
        my $v = $1; my %e = (amp => "&", lt => "<", gt => ">", quot => "\"", apos => "\x27");
        $v =~ s/&(amp|lt|gt|quot|apos);/$e{$1}/g; $v =~ s/&#x([0-9A-Fa-f]+);/chr hex $1/ge; $v =~ s/&#([0-9]+);/chr $1/ge;
        print $v' "$1"
}
# form_action ID_OR_NAME < HTML: the action of the form whose id or name is given, its character references resolved.
form_action() {
    perl -e 'local $/; my $h = <STDIN>; my $n = shift; $h =~ /<form\b[^>]*\b(?:id|name)="\Q$n\E"[^>]*>/i or exit 1;
        my $f = $&; $f =~ /\baction="([^"]*)"/i or exit 1; my $v = $1; $v =~ s/&amp;/&/g; print $v' "$1"
}
base64_decode() { perl -MMIME::Base64 -e 'local $/; binmode STDOUT; print decode_base64(<STDIN>)'; }
raw_inflate() {
    perl -MCompress::Raw::Zlib -e 'local $/; binmode STDIN; binmode STDOUT; my $in = <STDIN>;
        my ($i) = Compress::Raw::Zlib::Inflate->new(-WindowBits => -MAX_WBITS()); my $o;
        my $s = $i->inflate($in, $o); $s == Z_STREAM_END() or die "inflate: $s\n"; print $o'
}

# keep PARAMETER FILE: the SAML message of the last exchange, from the Location of a redirect (HTTP-Redirect) or from
# the auto-submitted form of the page (HTTP-POST), decoded into FILE. Prints the binding and what came with it.
keep() {
    local parameter=$1 file=$2 url
    url=$(location)
    if [ -n "$url" ] && printf '%s' "$url" | query_param "$parameter" > /dev/null; then
        printf '%s' "$url" | query_param "$parameter" | base64_decode | raw_inflate > "$file"
        echo "  $(basename "$file"): HTTP-Redirect to ${url%%\?*}, parameters: $(printf '%s' "$url" | query_names)"
    elif form_field "$parameter" < "$work/$step.b" > /dev/null; then
        form_field "$parameter" < "$work/$step.b" | base64_decode > "$file"
        echo "  $(basename "$file"): HTTP-POST to $(form_action saml-post-binding < "$work/$step.b")"
    else
        fail "step $step: no $parameter in the response (HTTP $(status))."
    fi
}
# deliver: carries the SAML message of the last exchange to where it goes, as a browser would.
deliver() {
    local url
    url=$(location)
    if [ -n "$url" ]; then
        request GET "$url"
    else
        local action fields=() field value
        action=$(form_action saml-post-binding < "$work/$step.b")
        for field in SAMLRequest SAMLResponse RelayState; do
            if value=$(form_field "$field" < "$work/$step.b"); then
                fields+=(--data-urlencode "$field=$value")
            fi
        done
        request POST "$action" "${fields[@]}"
    fi
}
# follow_until PREFIX: follows the redirects of the last exchange until one goes to PREFIX, kept in $reached.
follow_until() {
    local prefix=$1 url hops=0
    reached=
    while :; do
        url=$(location)
        [ -n "$url" ] || fail "step $step: HTTP $(status) where a redirect to $prefix was expected."
        case $url in "$prefix"*) reached=$url; return ;; esac
        hops=$((hops + 1))
        [ "$hops" -le 10 ] || fail "more than 10 redirects before $prefix."
        request GET "$url"
    done
}

mkdir -p "$out"
for i in $(seq 1 90); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "$base/realms/sp/broker/idp/endpoint/descriptor" || true)
    [ "$code" = 200 ] && break
    [ "$i" -lt 90 ] || fail 'Keycloak did not answer on port 8180 within 180 s.'
    sleep 2
done
echo "Keycloak $version on $base, capture of $day into $out"

echo 'Metadata'
request GET "$base/realms/idp/protocol/saml/descriptor"
cp "$work/$step.b" "$(name idp metadata)"
echo "  $(basename "$(name idp metadata)"): GET /realms/idp/protocol/saml/descriptor"
request GET "$base/realms/sp/broker/idp/endpoint/descriptor"
cp "$work/$step.b" "$(name sp metadata)"
echo "  $(basename "$(name sp metadata)"): GET /realms/sp/broker/idp/endpoint/descriptor"

echo 'Login'
request GET "$base/realms/sp/protocol/openid-connect/auth?client_id=capture&response_type=code&scope=openid&redirect_uri=$(printf '%s' "$client_redirect" | sed 's|:|%3A|g; s|/|%2F|g')&kc_idp_hint=idp"
follow_until "$base/realms/idp/"
keep SAMLRequest "$(name sp authn-request)"
deliver
login=$(form_action kc-form-login < "$work/$step.b") || fail "step $step: no login form at realm idp (HTTP $(status))."
request POST "$login" --data-urlencode "username=$username" --data-urlencode "password=$password" --data-urlencode credentialId=
keep SAMLResponse "$(name idp response)"
deliver
follow_until "$client_redirect"
code=$(printf "%s" "$reached" | query_param code) || fail "no authorization code at the client redirect."
request POST "$base/realms/sp/protocol/openid-connect/token" --data-urlencode grant_type=authorization_code \
    --data-urlencode "code=$code" --data-urlencode "redirect_uri=$client_redirect" --data-urlencode client_id=capture
id_token=$(perl -MJSON::PP -e 'local $/; print JSON::PP->new->decode(<STDIN>)->{id_token} // exit 1' < "$work/$step.b") \
    || fail "step $step: no id_token (HTTP $(status))."
echo "  logged in at the client of realm sp"

echo 'Logout'
request GET "$base/realms/sp/protocol/openid-connect/logout" -G --data-urlencode "id_token_hint=$id_token" \
    --data-urlencode "post_logout_redirect_uri=$client_redirect"
[ -n "$(location)" ] || form_field SAMLRequest < "$work/$step.b" > /dev/null || fail "step $step: realm sp sent no LogoutRequest (HTTP $(status))."
keep SAMLRequest "$(name sp logout-request)"
deliver
keep SAMLResponse "$(name idp logout-response)"
deliver
follow_until "$client_redirect"
echo "  logged out, back at the client of realm sp"
