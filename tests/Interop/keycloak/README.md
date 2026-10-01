# Keycloak, the second interoperability target

Story #14, sections 9.4 and 9.5 of `spec/model.md`: Keycloak as an identity provider (realm `idp`) and as a service
provider (realm `sp`, whose SAML identity provider `idp` brokers the login to realm `idp`), in one container, run by
hand, never in the CI and never a dependency of the package. It reinforces the judge of 9.5 (SimpleSAMLphp) and is
not a condition of it. The first phase built the installation and captured what two Keycloaks write to each other
(sections Installation to Findings); the second plays the model against Keycloak, both ways, as an identity provider
behind realm `sp`'s broker and as a service provider behind realm `idp` (section The exchange with the model and
after). `castor keycloak` runs both.

## Versions

| | |
|---|---|
| Keycloak | `quay.io/keycloak/keycloak:26.7.4`, manifest `sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c`, published on 16 September 2026 |
| How the tag was chosen | On 30 September 2026, the highest `x.y.z` tag of the registry, whose manifest is also the one of `latest` (`nightly` is not a release), over every page of the listing: `for page in 1 2 3; do curl -s "https://quay.io/api/v1/repository/keycloak/keycloak/tag/?limit=100&onlyActiveTags=true&page=$page"; done \| jq -r '.tags[] \| "\(.name) \(.manifest_digest) \(.last_modified)"' \| sort -V`, until a page answers `"has_additional": false` |
| Mode | `start-dev`: HTTP, the H2 database inside the container, the realms imported at startup from `realms/` |
| Port | 8180 on the host's loopback only, `127.0.0.1`, and in the container (8081 and 8082 are SimpleSAMLphp's, story #11); the image pinned by the manifest above |
| Machine of the capture | macOS 26 (Darwin 25.6), Docker 29.8.1, Docker Compose 5.5.1, GNU bash 3.2.57, curl 8.7.1, perl 5.34.1 |
| The exchange | `ghcr.io/spomky-labs/phpqa:8.5`, manifest `sha256:55fb69b22faad3c0e2ddcb4b76f66c1a5e664ea02acea1708a844e747a7c6dec` (PHP 8.5.10, libcurl 8.14.1), the package of this repository through its `vendor/autoload.php`; castor 1.7.0 on the host; xmlsec1 1.3.7 on Alpine 3.22 |

## Installation

From the root of the repository:

```
docker compose -f tests/Interop/keycloak/compose.yaml up -d
```

Keycloak imports `realms/idp.json` and `realms/sp.json` on its first start (the log says `Realm 'idp' imported`,
`Realm 'sp' imported`) and answers on `http://localhost:8180` after about ten seconds. The realm keys are generated
at import, so every `docker compose ... down` then `up` starts from new keys and new users; the metadata captured in
one run are the ones that verify the documents of that run.

| URL | What |
|---|---|
| `http://localhost:8180/realms/idp/protocol/saml` | the single sign-on and single logout service of realm `idp` |
| `http://localhost:8180/realms/idp/protocol/saml/descriptor` | the metadata of realm `idp`, identity provider |
| `http://localhost:8180/realms/sp/broker/idp/endpoint` | the assertion consumer and single logout service of the broker of realm `sp` |
| `http://localhost:8180/realms/sp/broker/idp/endpoint/descriptor` | the metadata of the broker, service provider |
| `http://localhost:8180/admin` | the admin console, user `admin`, password `admin` (disposable) |

The entity IDs are the realm URLs, `http://localhost:8180/realms/idp` and `http://localhost:8180/realms/sp`. In
`start-dev` Keycloak builds its URLs from the `Host` of the request: everything is addressed as `localhost:8180`, from
the host (curl) and from inside the container (the broker reading the metadata of realm `idp`), so that one URL names
each endpoint in every document.

- **Realm `idp`**: the SAML client `http://localhost:8180/realms/sp` (the broker's entity ID), whose valid redirect URI
  and single logout URL are the broker endpoint; the disposable test user `alice`, password `alice`,
  `alice@example.test`, Alice Test.
- **Realm `sp`**: the SAML identity provider `idp` pointing to realm `idp`, bound to the flow
  `first broker login without review profile`, a copy of Keycloak's `first broker login` without its `Review Profile`
  execution; the public OpenID Connect client `capture`, which starts a login toward that identity provider
  (`kc_idp_hint=idp`) and a logout (`id_token_hint`), redirect URI `http://localhost:8180/capture` (nothing answers
  there: the capture script reads the redirect and stops).

## Keycloak's defaults, and the settings that differ

**An import applies no default.** Measured on 26.7.4: a SAML client created through the admin REST API with nothing
but its `clientId` and `protocol` (`kcadm.sh create clients -r idp -s clientId=probe -s protocol=saml`) carries nine
SAML attributes the server adds, and `frontchannelLogout` on; the same client in an imported realm file carries none
of them, and `frontchannelLogout` off. A user created through the REST API gets the realm's `default-roles-idp`; an
imported one gets no role. The server adds nothing to a SAML identity provider created through the REST API; its
defaults are those of the form of the admin console. So the realm files write Keycloak's defaults out, as an
administrator gets them:

- the SAML client of realm `idp` carries the nine attributes the REST API adds, read back with
  `kcadm.sh get clients -r idp -q clientId=probe`: `saml.allow.ecp.flow=false`, `saml.authnstatement=true`,
  `saml.client.signature=true`, `saml.force.post.binding=true`, `saml.server.signature=true`,
  `saml.signature.algorithm=RSA_SHA256`, `saml_force_name_id_format=false`, `saml_name_id_format=username`,
  `saml_signature_canonicalization_method=http://www.w3.org/2001/10/xml-exc-c14n#`, and `frontchannelLogout` on;
  `saml.assertion.signature` and `saml.encrypt` are not among them, which the console shows as "Sign assertions" and
  "Encrypt assertions" off;
- the user holds `default-roles-idp`;
- the SAML identity provider of realm `sp` carries the defaults of the console's form (`SamlGeneralSettings-*.js` in
  `org.keycloak.keycloak-admin-ui-26.7.4.jar`): `validateSignature=true`, `wantAssertionsSigned=true`,
  `nameIDPolicyFormat=...:nameid-format:persistent`, `principalType=SUBJECT`, `allowCreate=true`,
  `entityId=<realm URL>`, `allowedClockSkew=0`, `attributeConsumingServiceIndex=0`; the form also sets
  `sendIdTokenOnLogout=true`, which only `OIDCIdentityProviderConfig` reads in 26.7.4 and is left out; the
  switches the form leaves off are written `false` where they decide the shape of a document (`postBindingResponse`,
  `postBindingAuthnRequest`, `postBindingLogout`, `wantAuthnRequestsSigned`, `wantAssertionsEncrypted`) and left out
  elsewhere, off either way.

Everything else is Keycloak's default. The settings that differ:

| Where | Setting | Default | Here | Why |
|---|---|---|---|---|
| `compose.yaml` | `--http-port` | 8080 | 8180 | The port of this installation, the same inside the container and on the host, so that `localhost:8180` names Keycloak from both |
| `compose.yaml` | `--import-realm` | no import | the files of `realms/` | The realms reproducible from the repository |
| `compose.yaml` | `KC_BOOTSTRAP_ADMIN_USERNAME`, `KC_BOOTSTRAP_ADMIN_PASSWORD` | no admin user | `admin`, `admin` | Reading the effective configuration back with `kcadm.sh`; disposable, like the container |
| realm `idp`, SAML client | `saml.client.signature` ("Client signature required") | `true` | `false` | The broker signs no request by default (`wantAuthnRequestsSigned` off), and its key, generated at import, cannot be written in the file of realm `idp`: with the default, realm `idp` refuses the broker's `AuthnRequest` (`error="invalid_signature"`, "Client does not have a public key", HTTP 400, measured on 30 September 2026). Request signatures travel in the query string of HTTP-Redirect, which is `saml2-bindings`' judge, not this package's |
| realm `idp`, SAML client | `saml_single_logout_service_url_post` | empty | the broker endpoint | Where realm `idp` sends its `LogoutResponse`; Keycloak has no default for it |
| realm `sp`, identity provider `idp` | `wantAssertionsSigned` ("Want Assertions signed") | `true` | `false` | Realm `idp` signs the response and not the assertion by default: with the console's default the broker refuses its response (`error="invalid_signature"`, HTTP 400, measured on 30 September 2026 with `kcadm.sh update identity-provider/instances/idp -r sp -s config.wantAssertionsSigned=true`) |
| realm `sp`, identity provider `idp` | `useMetadataDescriptorUrl`, `metadataDescriptorUrl` | off, empty | on, the metadata of realm `idp` | `validateSignature` needs the certificate of realm `idp`, generated at import: the broker reads it from that realm's metadata, as M-3 has the model do |
| realm `sp`, identity provider `idp` | `firstBrokerLoginFlowAlias` | `first broker login` | `first broker login without review profile` | No review screen during the scripted login (story #14) |
| realm `sp` | required action `VERIFY_PROFILE` | enabled | disabled | The assertion of realm `idp` carries no e-mail, first or last name by default; without `Review Profile`, the user profile of realm `sp` asks for them at the end of the first login ("Update account information", measured), which the removal of the review step is meant to avoid. The other thirteen required actions are written as Keycloak creates them, since an imported list replaces the default one |
| realm `sp` | client `capture` | none | a public OpenID Connect client | The browser side of the broker: it starts the login and the logout |

Under their defaults, a Keycloak broker and a Keycloak SAML client do not interoperate, either way: the client
requires a signed request (`saml.client.signature=true`) that the broker does not sign (`wantAuthnRequestsSigned`
off), and the broker requires a signed assertion (`wantAssertionsSigned=true`) that the client does not sign
(`saml.assertion.signature` absent). Each of the two settings above lifts one of the two refusals, both measured.

## Capture

From the root of the repository, Keycloak started as above:

```
bash tests/Interop/keycloak/capture.sh
docker compose -f tests/Interop/keycloak/compose.yaml down
```

`capture.sh` needs bash 3.2 or later, curl and perl with its core modules. It waits for Keycloak (180 s at most), then
plays the exchange with curl and one cookie jar, following no redirect by itself, as a browser would:

1. `GET /realms/idp/protocol/saml/descriptor` and `GET /realms/sp/broker/idp/endpoint/descriptor`: both metadata,
   kept as served.
2. `GET /realms/sp/protocol/openid-connect/auth?client_id=capture&response_type=code&scope=openid&redirect_uri=...&kc_idp_hint=idp`:
   realm `sp` redirects to its broker, which redirects to realm `idp` with the `AuthnRequest` in the query string
   (HTTP-Redirect): kept.
3. That redirect followed, the login form of realm `idp` is posted with `alice` and `alice`; realm `idp` answers with
   the page whose form carries the `Response` (HTTP-POST): kept.
4. The form posted to the broker endpoint; the redirects of the first broker login followed to the redirect URI of
   `capture`; the authorization code exchanged for the tokens.
5. `GET /realms/sp/protocol/openid-connect/logout?id_token_hint=...&post_logout_redirect_uri=...`: realm `sp` ends the
   session and its broker sends the `LogoutRequest` to realm `idp` (HTTP-Redirect): kept; realm `idp` answers with the
   `LogoutResponse` (HTTP-POST): kept; posted to the broker, which redirects to the client.

A document HTTP-Redirect carries is URL-decoded, base64-decoded and inflated (raw DEFLATE, no zlib header); one
HTTP-POST carries has the character references of the form value resolved, then is base64-decoded. Each is written
byte for byte as decoded, into `tests/Fixture/real/keycloak-<version>-<idp|sp>-<document>-<YYYY-MM-DD>.xml`, where
`idp` or `sp` names the realm that produced it, the version is read from `compose.yaml` and the date is the UTC day
of the run. The output of the run of 30 September 2026 that produced the committed files:

```
Keycloak 26.7.4 on http://localhost:8180, capture of 2026-09-30 into .../tests/Fixture/real
Metadata
  keycloak-26.7.4-idp-metadata-2026-09-30.xml: GET /realms/idp/protocol/saml/descriptor
  keycloak-26.7.4-sp-metadata-2026-09-30.xml: GET /realms/sp/broker/idp/endpoint/descriptor
Login
  keycloak-26.7.4-sp-authn-request-2026-09-30.xml: HTTP-Redirect to http://localhost:8180/realms/idp/protocol/saml, parameters: SAMLRequest RelayState
  keycloak-26.7.4-idp-response-2026-09-30.xml: HTTP-POST to http://localhost:8180/realms/sp/broker/idp/endpoint
  logged in at the client of realm sp
Logout
  keycloak-26.7.4-sp-logout-request-2026-09-30.xml: HTTP-Redirect to http://localhost:8180/realms/idp/protocol/saml, parameters: SAMLRequest RelayState
  keycloak-26.7.4-idp-logout-response-2026-09-30.xml: HTTP-POST to http://localhost:8180/realms/sp/broker/idp/endpoint
  logged out, back at the client of realm sp
```

Keycloak brokers the logout: the broker sends a `LogoutRequest` to realm `idp` and completes on its
`LogoutResponse`. Neither redirect carried a detached signature (no `SigAlg`, no `Signature` parameter): the broker
signs no request under its defaults.

## Verification by xmlsec1

Every signature of the captured documents is verified by xmlsec1, which shares nothing with Keycloak's Java stack,
under the signing certificate of the producer's metadata captured in the same run, with the SAML `ID` attributes
declared (`Response`, `AuthnRequest`, `LogoutRequest`, `LogoutResponse`, `Assertion`, `EntityDescriptor`), the command
of `xml-security`'s `castor xmlsec` extended to the protocol messages:

```
docker run --rm -v "$PWD:/project:ro" -w /project alpine:3.22 sh -c \
    'apk add -q xmlsec libxml2-utils openssl >/dev/null && sh tests/Interop/keycloak/verify.sh tests/Fixture/real'
```

`verify.sh` verifies each `ds:Signature` child of the root and of a direct `saml:Assertion` child on its own
(`--node-xpath`), so that a document holding two signatures has both verified. Two controls per signature must fail:
the same verification under a throwaway RSA key, which shows that xmlsec1 took the key from the metadata and not from
the certificate the message carries in its `KeyInfo`, and the verification of a copy whose signed `IssueInstant` is
altered. On 30 September 2026, with xmlsec1 1.3.7 (OpenSSL 3.5.9) on Alpine 3.22.6:

```
OK   keycloak-26.7.4-idp-logout-response-2026-09-30 /*/*[local-name()="Signature"]: verified under keycloak-26.7.4-idp-metadata-2026-09-30.xml; throwaway key and altered copy refused
--   keycloak-26.7.4-idp-metadata-2026-09-30: no signature
OK   keycloak-26.7.4-idp-response-2026-09-30 /*/*[local-name()="Signature"]: verified under keycloak-26.7.4-idp-metadata-2026-09-30.xml; throwaway key and altered copy refused
--   keycloak-26.7.4-sp-authn-request-2026-09-30: no signature
--   keycloak-26.7.4-sp-logout-request-2026-09-30: no signature
--   keycloak-26.7.4-sp-metadata-2026-09-30: no signature
2 signatures, 0 failures.
```

Two documents are signed, both by realm `idp`, one signature each; the four others carry none.

`verify.sh` would verify both signatures of a document signed twice (a response and its assertion); no document of
this capture holds two, so that path is not exercised by Keycloak's defaults.

## What realm `idp` signs by default

**The response, and not the assertion**, as section 9.5 of the specification expected; confirmed on 30 September 2026.

- **The capture.** In `keycloak-26.7.4-idp-response-2026-09-30.xml` the one `dsig:Signature` is a direct child of
  `samlp:Response`, right after its `saml:Issuer`, and its one `Reference` has `URI="#ID_68d700b7-9458-4006-9cff-06ee97ed6164"`,
  the `ID` of the response; the `saml:Assertion` has no `Signature` child. xmlsec1 verifies that signature under the
  certificate of realm `idp`'s metadata, and refuses it under a throwaway key and on an altered copy (above).
- **The configuration.** The SAML client the admin REST API creates from a `clientId` and a `protocol` alone carries
  `saml.server.signature=true` (the console's "Sign documents") and no `saml.assertion.signature` ("Sign assertions",
  off). The client of realm `idp` carries the same.
- **The consequence.** The broker as the console creates it wants the assertion signed (`wantAssertionsSigned=true`)
  and refuses this response: `error="invalid_signature"`, HTTP 400 at the broker endpoint. For the model, a Keycloak
  response under its defaults is the branch `SignatureCoverage::Response` of M-2, which SimpleSAMLphp's defaults
  leave aside.

The other defaults of realm `idp` as an identity provider, read on the same capture:

| | |
|---|---|
| Encryption | None: the response holds a `saml:Assertion` in clear; `saml.encrypt` is not among the attributes the REST API sets ("Encrypt assertions" off) |
| Signature algorithm | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`, with the realm's generated RSA key of 2048 bits, its certificate self-signed (`CN=idp`, ten years) |
| Digest algorithm | `http://www.w3.org/2001/04/xmlenc#sha256` |
| Canonicalization | `http://www.w3.org/2001/10/xml-exc-c14n#` for `SignedInfo`; the transforms are `enveloped-signature` then `xml-exc-c14n#`; no `InclusiveNamespaces` anywhere |
| Signature form | Enveloped, prefix `dsig`, after the `Issuer`; `KeyInfo` holds a `KeyName` (the key ID) and an `X509Data` with the certificate |
| `NameID` format | Observed: `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`, value `G-` and a UUID, because the broker's `NameIDPolicy` asks for it and the client does not force its own (`saml_force_name_id_format=false`). The client's configured format, `saml_name_id_format=username`, is not exercised by this exchange |
| `xsi:type` on attribute values | Yes: `xsi:type="xs:string"` on every `saml:AttributeValue`, with `xmlns:xs` and `xmlns:xsi` declared on that element itself |
| Attributes | The default client scope `role_list`: one `saml:Attribute Name="Role"` per role of the user, composites expanded, realm roles (`default-roles-idp`, `offline_access`, `uma_authorization`) and roles of the client `account` (`manage-account`, `manage-account-links`, `view-profile`) alike, `NameFormat` basic, one value each |
| Binding of the response | HTTP-POST ("Force POST binding" on by default), although the request asked for HTTP-Redirect |

## Measurements

One row per captured document. The windows are measured against the `IssueInstant` of the assertion
(`10:27:56.329Z`), which its `Conditions` and its confirmation belong to; the response's `IssueInstant` is 2 ms later
(`.331Z`) and the `AuthnInstant` 3 ms later (`.332Z`). Every `ID` is `ID_` followed by a UUID, 39 characters; the
longest URI has 54 characters.

| Document | Bytes | Signed | Algorithms, `InclusiveNamespaces` | `Conditions` against `IssueInstant` | Bearer `NotOnOrAfter` against `IssueInstant` | `SessionNotOnOrAfter` | Fractional digits | `NameID` format | Attributes, most values | `xsi:type` | `AudienceRestriction` | `SessionIndex` | `Destination` |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `idp-metadata` | 3 374 | nothing | none | | | | no time, no `validUntil` | lists `persistent`, `transient`, `1.1:unspecified`, `1.1:emailAddress` | | | | | |
| `sp-metadata` | 1 506 | nothing | none | | | | no time, no `validUntil` | lists `persistent` | | | | | |
| `sp-authn-request` | 714 | nothing, HTTP-Redirect without `SigAlg` | none | | | | 3 | asks `persistent`, `AllowCreate="true"` | | | | | the single sign-on service of realm `idp` |
| `idp-response` | 5 695 | the `Response`, not the `Assertion` | rsa-sha256, sha256, exc-c14n, transforms enveloped then exc-c14n; no `InclusiveNamespaces` | `NotBefore` 2 s before, `NotOnOrAfter` 58 s after: 60 s wide | 298 s after (`NotBefore` + 300 s) | `AuthnInstant` + 36 000 s (10 h) | 3, on all seven times | `persistent`, 38 characters | 6 `Attribute`, all named `Role`, 1 value each | `xs:string` on every value | 1, with 1 `Audience`, the broker's entity ID | 62 characters, `<24 characters>::<UUID>` | the broker endpoint, equal to the bearer `Recipient` |
| `sp-logout-request` | 639 | nothing, HTTP-Redirect without `SigAlg` | none | | no `NotOnOrAfter` | | 3 | `persistent`, the `NameID` of the response | | | | 1, the one of the response | the single logout service of realm `idp` |
| `idp-logout-response` | 2 716 | the `LogoutResponse` | as the response | | | | 3 | | | | | | the broker endpoint |

The widths equal defaults of realm `idp` read with `kcadm.sh get realms/idp`: `accessCodeLifespan` 60 s for
`Conditions`, `ssoSessionMaxLifespan` 36 000 s for `SessionNotOnOrAfter`; the bearer window of 300 s equals both
`accessTokenLifespan` and `accessCodeLifespanUserAction`, and which of the two sets it is not established here. No
count comes near a bound of section 7 of the specification or of core.md §7 (depth 6, 16 namespace declarations in
the response, at most 8 attributes on an element).

## Findings

Each document read against sections 4, 6, 7 and 8 of `spec/model.md`, and against `xml-security`'s `core.md` and
`dsig.md`, whose refusals the model lets through (section 5.8). Nothing here changes the specification; each finding
is for the coordinator, who alone edits it.

**What the model would refuse.**

1. **`sp-authn-request`: `ProtocolBinding` HTTP-Redirect.** Refused as `Unsupported` by 6.2 step 4 and section 8 (a
   `ProtocolBinding` other than HTTP-POST): the broker writes HTTP-Redirect whenever its "HTTP-POST binding response"
   is off, its default in the console's form and in an import that leaves it out, although Keycloak's own identity
   provider answers with HTTP-POST anyway. As it stands, the model as an identity provider refuses every login of a
   Keycloak broker left at its defaults; with `postBindingResponse` on, the broker writes
   `ProtocolBinding="...:HTTP-POST"` (measured on 30 September 2026 with
   `kcadm.sh update identity-provider/instances/idp -r sp -s config.postBindingResponse=true`). Either the refusal
   stays and is documented with Keycloak's name, or 6.2 step 4 answers such a request over HTTP-POST, as Keycloak's
   identity provider does: a question for the specification.
2. **`sp-logout-request`: unsigned.** Refused as `SignatureRequired` by M-2 and 6.3 (Profiles §4.4.4.1, as the
   specification cites it): the request carries no `ds:Signature` and its redirect no `SigAlg` or `Signature`, so
   neither `validate()` nor `validateAuthenticatedByBinding()` accepts it. The broker signs no request under its
   defaults (`wantAuthnRequestsSigned` off); realm `idp` accepted it only because of the setting of this installation
   (`saml.client.signature=false`). A refusal to document with Keycloak's name. With `wantAuthnRequestsSigned` on,
   both redirects of the broker carry `SigAlg` and `Signature` (measured the same day), the case of
   `validateAuthenticatedByBinding()` once `saml2-bindings` has verified the query string.

**What the model would accept, with what it reads.**

3. **`idp-response`.** Accepted under the default `TimeBounds` with a clock frozen at its `IssueInstant`, as
   `SignatureCoverage::Response` (6.1 step 5: the assertion unsigned, read from the response's `Verified::$document`).
   Its `Conditions` close 58 s after issue, so it is refused by M-7 from 238 s after issue (58 s plus the default skew
   of 180 s), before `maxMessageAge` (300 s) would refuse it.
4. **`idp-logout-response`.** Accepted by 6.4: signed, `Destination`, `InResponseTo` equal to the `ID` of the captured
   `LogoutRequest`, status `Success`. Its `Issuer` is unprefixed, in the default namespace the root declares; the
   model reads names by namespace and local name, so nothing changes.
5. **`idp-metadata`.** Read with `readTrusted()`; `readSigned()` has nothing to verify (unsigned). Its single sign-on
   and single logout services also list SOAP and HTTP-Artifact, which 6.5 step 6 drops; its four `NameIDFormat` are
   formats of Core §8.3; its `KeyInfo` holds a `KeyName` next to the certificate, a hint 6.5 step 5 does not read.
6. **`sp-metadata`.** Read with `readTrusted()`. The broker publishes no `KeyDescriptor`, so `verificationKeys()` is
   `null`; with `AuthnRequestsSigned="false"`, its unsigned requests are `Authentication::None` unless the model's
   own metadata wants them signed.
7. **Every document** passes `core.md` (no XML declaration, read as UTF-8, no DOCTYPE, absolute namespaces, IDs that
   are NCNames of 39 bytes, no libxml diagnostic under `xmllint --noout`) and `dsig.md` (D-3 transforms, D-4 exclusive
   canonicalization, D-5 algorithms, D-9 structure, D-16 RSA 2048, a `SignatureValue` of 256 bytes).

**Questions for the specification.**

8. **`md:ArtifactResolutionService`.** The metadata of realm `idp` carries one (SOAP, `index="0"`) before its single
   logout services. 6.5 names the endpoints it reads and the role descriptors it skips, not the other children the
   schema allows in an `IDPSSODescriptor` (`ArtifactResolutionService`, `ManageNameIDService`,
   `NameIDMappingService`, `AssertionIDRequestService`, `AttributeProfile`, `saml:Attribute`): skipped, or
   `MalformedMessage` under M-5? Keycloak's metadata loads only if skipped.
9. **The default assertion consumer service.** The broker's metadata lists three at one `Location`: HTTP-Redirect
   `index="1" isDefault="true"`, HTTP-POST `index="2"`, HTTP-Artifact `index="3"`. 6.5 step 6 keeps the first two.
   Whether `IndexedEndpoints::default()` (M-9, Metadata §2.2.3) runs over every kept endpoint or over the HTTP-POST
   ones decides whether a request naming no consumer service resolves to `index="2"` or to an endpoint that cannot
   carry a response; and `byLocation()` must choose among the HTTP-POST ones, since the three share a `Location`.
10. **Repeated attribute names.** The response carries six `saml:Attribute` named `Role`, one value each, where one
    attribute with six values would say the same. 6.1 step 11 neither refuses nor merges them; the model returns six
    `Attribute`, and whoever maps them to claims (`heidi/saml`) must know it.
11. **An empty `md:NameIDFormat`.** Observed in a trial run, not committed: with the broker's identity provider
    created through the API without `nameIDPolicyFormat`, the broker's metadata carries `<md:NameIDFormat></md:NameIDFormat>`.
    6.5 step 7 drops a URI that is not a format of Core §8.3; whether an empty one is dropped, or refused as a value
    that is not a URI (M-6), is not written.

**Observations, no rule touched.**

12. **ID entropy.** Every `ID` is `ID_` and a version 4 UUID, 122 random bits, below the 128 bits of Core §1.3.4 that
    6.6 step 2 of the specification writes to. The model checks an `ID` as an NCName within `maxIdLength` (M-6, I-8),
    not its entropy, and refuses nothing.
13. **`AuthnInstant` after `IssueInstant`.** The `AuthnInstant` is 3 ms after the assertion's `IssueInstant` and 1 ms
    after the response's. M-7 bounds it by `now + skew` only, so nothing is refused; a validator without skew would.
14. **`xsi:type` outside the signed bytes.** `xmlns:xs` is declared on each `AttributeValue` and named only in an
    attribute value, so exclusive canonicalization leaves it out of what the response's digest covers, as dsig.md
    §6.3 says of SimpleSAMLphp; 6.1 step 11 reads the value as text and never resolves the prefix.
15. **`WantAuthnRequestsSigned="true"`** in the metadata of realm `idp`, while its client for the broker requires no
    signature in this installation: the metadata states the realm's position, not the client's.
16. **The first login.** Removing `Review Profile`, as story #14 asks, is not enough with 26.7.4: the required action
    `VERIFY_PROFILE` asks for the profile at the end of the first login, and is disabled here (settings, above).

## `castor keycloak`

The task of `.castor/keycloak.php` runs the whole of this document from the root of the repository:

```
castor keycloak
```

Without an option it runs every stage in order: `--up` (`docker compose ... up -d`, the realms imported with new
keys), `--capture` (`capture.sh`, the first phase), `--exchange` (`exchange.php`, below), `--verify` (xmlsec1 over the
documents the model wrote and over Keycloak's), `--down` (`docker compose ... down`, run even when a stage fails).
Given one or more of these options, it runs those only. `--output` is where Keycloak's documents go: by default
`tmp-phpqa/keycloak/`, ignored by git and emptied of its `keycloak-*.xml` before a capture or an exchange, so that a
run from a clean checkout touches no fixture; the model's documents always go to `tmp-phpqa/keycloak/model/`. To renew
the fixtures, `--output=tests/Fixture/real` with the stages named, since both scripts name their files by the UTC day
and rewrite the files of that day: the committed exchange of 30 September 2026 was written by

```
docker compose -f tests/Interop/keycloak/compose.yaml up -d        # what castor keycloak --up runs
castor keycloak --exchange --verify --down --output=tests/Fixture/real
```

without `--capture`, which would have rewritten the six files of the first phase, captured the same day under the keys
of an earlier container. The same day, `castor keycloak` without an option ran every stage green from a stopped
Keycloak into `tmp-phpqa/keycloak/`.

The exchange runs in the phpqa image, in the network namespace of the Keycloak container, so that `localhost:8180`
names Keycloak there as in every URL it builds and checks (`Destination`, `Recipient`, the broker endpoint):

```
docker run --rm --init -i --user "$(id -u):$(id -g)" \
    --network container:$(docker compose -f tests/Interop/keycloak/compose.yaml ps -q keycloak) \
    -v "$PWD:/project" -w /project -e XDEBUG_MODE=off ghcr.io/spomky-labs/phpqa:8.5 \
    php tests/Interop/keycloak/exchange.php <output> tmp-phpqa/keycloak/model
```

It needs the dependencies installed (`castor install`): it loads the package from `vendor/autoload.php`, and
`InMemoryReplayGuard` from `tests/Support/`.

## The exchange with the model

Section 9.5's second half, played against Keycloak: every message over HTTP-POST, base64 in a form field, the form
written in `exchange.php` and not in `saml2-bindings`; curl as the browser, one cookie jar per direction, following no
redirect by itself; the test keys of `tests/Fixture/keys/`, the identity provider pair for the model's identity
provider, the service provider pair for its service provider; for the two ports of section 5.2, a PSR-20 clock written
in the script, which reads the machine's time in UTC, and `InMemoryReplayGuard` of `tests/Support/`.

### The model's two roles, and what Keycloak makes of their metadata

| | The model's identity provider | The model's service provider |
|---|---|---|
| Entity ID | `https://idp.saml2-model.test/metadata` | `https://sp.saml2-model.test/metadata` |
| Services, all on HTTP-POST | single sign-on `https://idp.saml2-model.test/sso`, single logout `https://idp.saml2-model.test/slo` | assertion consumer `https://sp.saml2-model.test/acs`, `index="0"`, `isDefault="true"`; single logout `https://sp.saml2-model.test/slo` |
| Flags | `WantAuthnRequestsSigned="true"`; `NameIDFormat` persistent | `AuthnRequestsSigned="true"`, `WantAssertionsSigned="false"` |
| Key | `idp-signing-certificate.pem`, `use="signing"` | `sp-signing-certificate.pem`, `use="signing"` |
| Written by | `MetadataWriter`, signed with `idp-signing-key.pem` | `MetadataWriter`, signed with `sp-signing-key.pem` |

Nothing answers at these URLs: Keycloak's auto-submitted forms say where a message goes, and the script reads the form
instead of posting it. Keycloak is configured from these two documents by its own importers, through the admin REST
API and the disposable administrator of `compose.yaml`, as an administrator does who imports a metadata file in the
console:

- **Realm `sp`, identity provider `model`.** `POST /admin/realms/sp/identity-provider/import-config` (multipart,
  `providerId=saml`, `file=` the model's identity provider metadata) returns the configuration it reads from the
  document; `POST /admin/realms/sp/identity-provider/instances` creates the identity provider with it, over the
  defaults of the console's form that the import does not return (`entityId` the realm URL, `wantAssertionsSigned=true`,
  `nameIDPolicyFormat` persistent, `principalType=SUBJECT`, `allowCreate=true`, `allowedClockSkew=0`,
  `attributeConsumingServiceIndex=0`, as in the first phase) and the first broker login flow without review of
  `realms/sp.json`.
- **Realm `idp`, client `https://sp.saml2-model.test/metadata`.** `POST /admin/realms/idp/client-description-converter`
  (the model's service provider metadata as the body) returns a client representation; `POST /admin/realms/idp/clients`
  creates it, and the server adds its defaults to what the converter did not set, as the first phase measured.

Both are deleted first when they exist, with the user the model's subject became in realm `sp` on an earlier run (the
deletion of the identity provider removes the user's link, not the user, and the first broker login would then ask to
link the account instead of creating it), so that an exchange can run again on a live container. The configuration
read back after the creation, measured on 30 September 2026:

| Where | Setting | Value | From |
|---|---|---|---|
| realm `sp`, identity provider `model` | `singleSignOnServiceUrl`, `singleLogoutServiceUrl` | the model's two services | import-config |
| | `postBindingAuthnRequest`, `postBindingResponse`, `postBindingLogout` | `true`, `true`, `true` | import-config: the metadata lists an HTTP-POST single sign-on service (below, finding 17) |
| | `wantAuthnRequestsSigned` | `true` | import-config, from `WantAuthnRequestsSigned="true"` |
| | `validateSignature`, `signingCertificate` | `true`, the identity provider test certificate | import-config, from the `KeyDescriptor` |
| | `idpEntityId`, `nameIDPolicyFormat` | the model's entity ID, persistent | import-config |
| | `addExtensionsElementWithKeyInfo`, `artifactBindingResponse`, `loginHint`, `enabledFromMetadata` | `false`, `false`, `false`, `true` | import-config |
| | `entityId`, `wantAssertionsSigned`, `principalType`, `allowCreate`, `allowedClockSkew`, `attributeConsumingServiceIndex` | `http://localhost:8180/realms/sp`, `true`, `SUBJECT`, `true`, `0`, `0` | the console's form |
| | `firstBrokerLoginFlowAlias` | `first broker login without review profile` | `realms/sp.json`: no review screen in a scripted login (story #14) |
| realm `idp`, client of the model | `saml.signing.certificate`, `saml_assertion_consumer_url_post`, `saml_single_logout_service_url_post`, `redirectUris` | the service provider test certificate, the model's two services, the consumer service | the converter |
| | `saml.client.signature` ("Client signature required") | `true`, Keycloak's default | the converter, from `AuthnRequestsSigned="true"` |
| | `saml.server.signature`, `saml.signature.algorithm`, `saml.authnstatement`, `saml.server.signature.keyinfo.ext` | `true`, `RSA_SHA256`, `true`, `false` | the converter |
| | `saml.assertion.signature` ("Sign assertions") | absent, off | the converter sets it only for `WantAssertionsSigned="true"`: realm `idp` signs the response only, its default |
| | `saml.force.post.binding`, `saml_name_id_format`, `saml_force_name_id_format`, `saml.allow.ecp.flow`, `saml_signature_canonicalization_method`, `frontchannelLogout` | `true`, `username`, `false`, `false`, exc-c14n, on | the server's defaults |

No setting of the first phase changes, and no setting is added by hand to make a direction pass: F1 and F2 are
answered by what the model's identity provider metadata says, read by Keycloak's own importer.

### The run

`exchange.php`, after the configuration:

1. **Keycloak's metadata**: realm `idp`'s and the broker `model`'s, kept, then read with `MetadataReader::readTrusted()`.
2. **Two controls**, each in a browser of its own, so that the logins below prove something: a response to a real
   request of the broker, its assertion signed by the service provider test key, which the broker was not given, is
   posted to the broker endpoint; an `AuthnRequest` signed by the identity provider test key, which realm `idp`'s
   client was not given, is posted to realm `idp`. Each must be refused by an error page, neither a redirect nor a form
   going on.
3. **The model as identity provider.** `GET /realms/sp/protocol/openid-connect/auth?...&kc_idp_hint=model`, the
   redirects followed to the broker's page, whose form posts the `AuthnRequest` to the model's single sign-on service:
   kept, validated by `AuthnRequestValidator::validate()` (HTTP-POST, a `ds:Signature`: the path of 6.2 for it), its
   assertion consumer service resolved in the broker's metadata. The model answers with `ResponseWriter::write()`, the
   identity provider test key, `SignedParts::Assertion` (the broker wants the assertion signed): the persistent subject
   `model-alice`, a bearer window and conditions of 300 s, a `SessionIndex`, two attributes (`email`, and `Role` with
   two values) without `xsi:type`; posted to the broker endpoint with the `RelayState` of the request and the cookie
   jar. The first broker login creates the user, and the redirects end at the client `capture` with a code, exchanged
   for the tokens. Then `GET /realms/sp/protocol/openid-connect/logout?id_token_hint=...`: the broker's page posts its
   `LogoutRequest` to the model's single logout service: kept, validated by `LogoutRequestValidator::validate()`; the
   model answers with `LogoutResponseWriter::write()`, signed, `Success`, posted to the broker's single logout service
   with the `RelayState`, and the redirects end at the client.
4. **The model as service provider.** `AuthnRequestWriter::write()`, signed with the service provider test key, the
   persistent format asked (`AllowCreate="true"`), HTTP-POST as `ProtocolBinding`, posted to realm `idp`'s single sign-on
   service with a `RelayState`; the login form posted with `alice`, `alice`; realm `idp`'s page posts the response to the
   model's consumer service with the same `RelayState`: kept, validated by `ResponseValidator::validate()` against
   `ExpectedResponse::toRequest()`. Then `LogoutRequestWriter::write()`, signed, the `NameID` and the `SessionIndex` of
   the accepted assertion, posted to realm `idp` with the same cookie jar; realm `idp`'s page posts its
   `LogoutResponse` to the model's single logout service: kept, validated by `LogoutResponseValidator::validate()`.

Keycloak's documents are written byte for byte as decoded from the form, into
`<output>/keycloak-<version>-exchange-<producer>-<document>-<YYYY-MM-DD>.xml`, where the producer is `idp` (realm
`idp`) or `broker` (realm `sp`'s identity provider `model`); the model's, serialized by `Core`'s `Serializer`, into
`tmp-phpqa/keycloak/model/model-<idp|sp>-<document>.xml`, with the two configurations read back as JSON. The output of
the run of 30 September 2026 that produced the committed files (the two lines of settings are those of the table
above):

```
Keycloak 26.7.4 on http://localhost:8180, exchange of 2026-09-30, Keycloak's documents into tests/Fixture/real, the model's into tmp-phpqa/keycloak/model
The model's metadata, given to Keycloak
  realm sp, identity provider model from import-config: addExtensionsElementWithKeyInfo=false, artifactBindingResponse=false, enabledFromMetadata=true, idpEntityId=https://idp.saml2-model.test/metadata, loginHint=false, nameIDPolicyFormat=urn:oasis:names:tc:SAML:2.0:nameid-format:persistent, postBindingAuthnRequest=true, postBindingLogout=true, postBindingResponse=true, signingCertificate=<1156 characters>, singleLogoutServiceUrl=https://idp.saml2-model.test/slo, singleSignOnServiceUrl=https://idp.saml2-model.test/sso, validateSignature=true, wantAuthnRequestsSigned=true
  realm idp, client https://sp.saml2-model.test/metadata from client-description-converter: saml.authnstatement=true, saml.client.signature=true, saml.server.signature=true, saml.server.signature.keyinfo.ext=false, saml.signature.algorithm=RSA_SHA256, saml.signing.certificate=<1156 characters>, saml_assertion_consumer_url_post=https://sp.saml2-model.test/acs, saml_single_logout_service_url_post=https://sp.saml2-model.test/slo
Keycloak's metadata
  keycloak-26.7.4-exchange-idp-metadata-2026-09-30.xml: GET /realms/idp/protocol/saml/descriptor
  keycloak-26.7.4-exchange-broker-metadata-2026-09-30.xml: GET /realms/sp/broker/model/endpoint/descriptor
  read by MetadataReader::readTrusted(): realm idp, 1 signing certificate; the broker, 1 signing certificate, AuthnRequestsSigned true, WantAssertionsSigned true
Controls: a signature by the other test key
  refused by the broker, a response whose assertion the service provider test key signed: HTTP 400, "Invalid signature in response from identity provider."
  refused by realm idp, an AuthnRequest the identity provider test key signed: HTTP 400, "Invalid requester"
The model as identity provider, realm sp's broker in front
  keycloak-26.7.4-exchange-broker-authn-request-2026-09-30.xml: HTTP-POST to https://idp.saml2-model.test/sso, fields SAMLRequest RelayState
  accepted by AuthnRequestValidator::validate(): XmlSignature, ID ID_fdae0d1a-7165-4939-be02-2cc70ac0b155, assertion consumer service http://localhost:8180/realms/sp/broker/model/endpoint index 1, ProtocolBinding urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST, NameIDPolicy urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
  the model's response _981f771ccb21b558615cb9197bcef828fdd54fcd, its assertion signed (SignedParts::Assertion), posted to http://localhost:8180/realms/sp/broker/model/endpoint
  logged in at the client of realm sp: preferred_username model-alice
  keycloak-26.7.4-exchange-broker-logout-request-2026-09-30.xml: HTTP-POST to https://idp.saml2-model.test/slo, fields SAMLRequest RelayState
  accepted by LogoutRequestValidator::validate(): XmlSignature, ID ID_7fb80c65-0821-4bee-a28d-1bd88def3f61, NameID model-alice, SessionIndex _2a9f36d46739894e683decb7f7705c0dcf19635a
  the model's LogoutResponse _c097cbdd5be29ffe3be98aad18125f4f9525e104, signed, posted to http://localhost:8180/realms/sp/broker/model/endpoint
  logged out, back at the client of realm sp
The model as service provider, realm idp in front
  the model's AuthnRequest _8b44214fbfab0a7dccde575a0028ce774831e27f, signed, posted to http://localhost:8180/realms/idp/protocol/saml
  keycloak-26.7.4-exchange-idp-response-2026-09-30.xml: HTTP-POST to https://sp.saml2-model.test/acs, fields SAMLResponse RelayState
  accepted by ResponseValidator::validate(): SignatureCoverage::Response, response ID_19abf153-cab9-41ae-9f81-76b13888fe0a, NameID G-41eee78d-0ec1-43d9-b7fc-584c8bccc500 (Persistent), SessionIndex _95NiAiPWiL8nAJmSq5Hlflp::e23c7b4f-7c1b-45c3-8ded-744f3c749829, 6 attributes
  the model's LogoutRequest _9f51ef48331c006c5d1afd246989666af224d283, signed, posted to http://localhost:8180/realms/idp/protocol/saml
  keycloak-26.7.4-exchange-idp-logout-response-2026-09-30.xml: HTTP-POST to https://sp.saml2-model.test/slo, fields SAMLResponse RelayState
  accepted by LogoutResponseValidator::validate(): XmlSignature, ID ID_0f8c9087-49ff-4053-bd42-a0faed07f994, status Success
Both directions completed.
```

The IDs of the model's two requests, `_8b44214fbfab0a7dccde575a0028ce774831e27f` and
`_9f51ef48331c006c5d1afd246989666af224d283`, are those `tests/Unit/Interop/KeycloakDocumentsTest.php` names as what
realm `idp`'s response and `LogoutResponse` answer.

### Results

| Direction | Result |
|---|---|
| The model as identity provider, the broker in front: login | Green. The broker's signed `AuthnRequest` accepted by the model (`Authentication::XmlSignature`); the model's response, its assertion signed, accepted by the broker, which completes the first broker login (user `model-alice` created) and redirects to its client with a code |
| The broker's logout toward the model | Green. The broker's signed `LogoutRequest` accepted by the model (`Authentication::XmlSignature`); the model's signed `LogoutResponse` accepted by the broker, which redirects to the client |
| The model as service provider, realm `idp` in front: login | Green. The model's signed `AuthnRequest` accepted by realm `idp`, which shows its login form; its response accepted by the model, `SignatureCoverage::Response` |
| The model's logout toward realm `idp` | Green. The model's signed `LogoutRequest` accepted by realm `idp`; its signed `LogoutResponse` accepted by the model (`Authentication::XmlSignature`, `Success`) |
| Controls | Both refused, HTTP 400: the broker verifies the assertion's signature under the certificate imported from the model's metadata, and realm `idp` the request's under the client's certificate |

Not played: realm `idp` sending a `LogoutRequest` to the model's service provider (a logout started at another
client of the same session), and every HTTP-Redirect exchange, whose detached signature is `saml2-bindings`' judge.
Keycloak's encrypted assertions are sub-spike 9e's.

## Verification of the exchange by xmlsec1

**What the model wrote**, the six documents of `tmp-phpqa/keycloak/model/`, each under the test certificate of the
role that signed it, by `tests/Fixture/oracle/verify-signatures.sh` (`castor xmlsec`'s script):

```
docker run --rm -i -v "$PWD:/project:ro" -w /project alpine:3.22 sh -c 'apk add -q xmlsec libxml2-utils >/dev/null 2>&1 && xmlsec1 --version && sh tests/Fixture/oracle/verify-signatures.sh tests/Fixture/keys/idp-signing-certificate.pem tmp-phpqa/keycloak/model/model-idp-logout-response.xml tmp-phpqa/keycloak/model/model-idp-metadata.xml tmp-phpqa/keycloak/model/model-idp-response.xml'
docker run --rm -i -v "$PWD:/project:ro" -w /project alpine:3.22 sh -c 'apk add -q xmlsec libxml2-utils >/dev/null 2>&1 && xmlsec1 --version && sh tests/Fixture/oracle/verify-signatures.sh tests/Fixture/keys/sp-signing-certificate.pem tmp-phpqa/keycloak/model/model-sp-authn-request.xml tmp-phpqa/keycloak/model/model-sp-logout-request.xml tmp-phpqa/keycloak/model/model-sp-metadata.xml'
```

On 30 September 2026, on the documents of the run above:

```
xmlsec1 1.3.7 (openssl)
Verification status: OK
tmp-phpqa/keycloak/model/model-idp-logout-response.xml: 1 signatures verified by xmlsec1.
Verification status: OK
tmp-phpqa/keycloak/model/model-idp-metadata.xml: 1 signatures verified by xmlsec1.
Verification status: OK
tmp-phpqa/keycloak/model/model-idp-response.xml: 1 signatures verified by xmlsec1.
xmlsec1 1.3.7 (openssl)
Verification status: OK
tmp-phpqa/keycloak/model/model-sp-authn-request.xml: 1 signatures verified by xmlsec1.
Verification status: OK
tmp-phpqa/keycloak/model/model-sp-logout-request.xml: 1 signatures verified by xmlsec1.
Verification status: OK
tmp-phpqa/keycloak/model/model-sp-metadata.xml: 1 signatures verified by xmlsec1.
```

Six documents, six signatures: the response carries one, its assertion's (`SignedParts::Assertion`). These documents
are not committed: each run draws new IDs and times, and the model's writers are judged by the suite (section 9.1)
and by the oracle of the CI.

**What Keycloak wrote**, by `verify.sh` over the output directory, with the command of the first phase; the documents
of the exchange are verified under the metadata the exchange captured, since the realm keys of that container are not
those of the first phase's:

```
OK   keycloak-26.7.4-exchange-broker-authn-request-2026-09-30 /*/*[local-name()="Signature"]: verified under keycloak-26.7.4-exchange-broker-metadata-2026-09-30.xml; throwaway key and altered copy refused
OK   keycloak-26.7.4-exchange-broker-logout-request-2026-09-30 /*/*[local-name()="Signature"]: verified under keycloak-26.7.4-exchange-broker-metadata-2026-09-30.xml; throwaway key and altered copy refused
--   keycloak-26.7.4-exchange-broker-metadata-2026-09-30: no signature
OK   keycloak-26.7.4-exchange-idp-logout-response-2026-09-30 /*/*[local-name()="Signature"]: verified under keycloak-26.7.4-exchange-idp-metadata-2026-09-30.xml; throwaway key and altered copy refused
--   keycloak-26.7.4-exchange-idp-metadata-2026-09-30: no signature
OK   keycloak-26.7.4-exchange-idp-response-2026-09-30 /*/*[local-name()="Signature"]: verified under keycloak-26.7.4-exchange-idp-metadata-2026-09-30.xml; throwaway key and altered copy refused
OK   keycloak-26.7.4-idp-logout-response-2026-09-30 /*/*[local-name()="Signature"]: verified under keycloak-26.7.4-idp-metadata-2026-09-30.xml; throwaway key and altered copy refused
--   keycloak-26.7.4-idp-metadata-2026-09-30: no signature
OK   keycloak-26.7.4-idp-response-2026-09-30 /*/*[local-name()="Signature"]: verified under keycloak-26.7.4-idp-metadata-2026-09-30.xml; throwaway key and altered copy refused
--   keycloak-26.7.4-sp-authn-request-2026-09-30: no signature
--   keycloak-26.7.4-sp-logout-request-2026-09-30: no signature
--   keycloak-26.7.4-sp-metadata-2026-09-30: no signature
6 signatures, 0 failures.
```

## Measurements of the exchange

The same reading as the first phase's, on the six documents of the exchange. Realm `idp`'s metadata has the shape of
the first phase's, element for element, with a new key.

| Document | Bytes | Signed | Against the first phase |
|---|---|---|---|
| `exchange-idp-metadata` | 3 374 | nothing | the same elements and attributes; another certificate and key name |
| `exchange-broker-metadata` | 2 610 | nothing | a `KeyDescriptor use="signing"` (the realm's key, with a `KeyName`), `AuthnRequestsSigned="true"`, and the HTTP-POST assertion consumer service first, `index="1" isDefault="true"`, HTTP-Redirect `index="2"` and HTTP-Artifact `index="3"` after it; single logout on HTTP-POST then HTTP-Redirect |
| `exchange-broker-authn-request` | 2 777 | the request, enveloped, rsa-sha256, sha256, exc-c14n; `KeyInfo` an `X509Data` without `KeyName` | `ProtocolBinding` HTTP-POST; `Destination` the model's single sign-on service; `ForceAuthn="false"`, `AttributeConsumingServiceIndex="0"`, no `IsPassive`; `NameIDPolicy` persistent, `AllowCreate="true"`; 3 fractional digits |
| `exchange-broker-logout-request` | 2 656 | the request, as above | the `NameID` and the `SessionIndex` of the model's assertion, persistent; no `NotOnOrAfter`, no `Reason` |
| `exchange-idp-response` | 5 664 | the `Response`, not the `Assertion` | the windows of the first phase: `Conditions` 2 s before and 58 s after the assertion's `IssueInstant`, bearer 298 s after, `SessionNotOnOrAfter` 10 h after the `AuthnInstant`; `NameID` persistent `G-` and a UUID, as the model's `NameIDPolicy` asked although the client's format is `username` (not forced); `AuthnContextClassRef` `unspecified`; the six `Role` attributes |
| `exchange-idp-logout-response` | 2 698 | the `LogoutResponse` | its `Issuer` unprefixed in the default namespace, as in the first phase |

## Findings of the exchange

Numbered after those of the first phase. F1 is finding 1, F2 finding 2.

**F1 and F2, answered by the model's metadata.**

17. **F1 does not arise when the broker is configured from the model's metadata.** Keycloak's `import-config` sets
    `postBindingAuthnRequest`, `postBindingResponse` and `postBindingLogout` together, to `true` whenever the metadata
    lists a single sign-on service on HTTP-POST, whatever its place among the services, and to `false` when it lists
    HTTP-Redirect only (measured on 30 September 2026 with four variants of the model's metadata: HTTP-POST only,
    HTTP-Redirect then HTTP-POST, HTTP-POST then HTTP-Redirect, all `true`; HTTP-Redirect only, all `false`). The
    broker then asks for `ProtocolBinding` HTTP-POST, and sends its requests over HTTP-POST. F1 stays for a broker
    configured by hand, whose form leaves `postBindingResponse` off, and for an identity provider metadata without an
    HTTP-POST single sign-on service. The specification refuses a response over HTTP-Redirect (section 8, 6.2 step 4),
    which HTTP-Redirect cannot carry (Profiles §4.1.2): the rule stands, and the metadata of `heidi/saml` listing an
    HTTP-POST single sign-on service is what makes a Keycloak broker comply.
18. **F2 does not arise when the model's metadata says `WantAuthnRequestsSigned="true"`.** `import-config` carries it to
    the broker's `wantAuthnRequestsSigned`, which signs both its `AuthnRequest` and its `LogoutRequest`, and publishes
    the realm's key in the broker's metadata (the first phase's had none); over HTTP-POST the signature is an enveloped
    `ds:Signature` that `validate()` verifies under that key. Without it, the broker's `LogoutRequest` is unsigned and
    refused (`SignatureRequired`, M-2), as the first phase found. The metadata of `heidi/saml`'s identity provider
    saying `WantAuthnRequestsSigned="true"` is what makes a Keycloak broker's logout acceptable.

**What Keycloak accepted from the model.**

19. **Attribute values without `xsi:type`.** The broker parsed the model's `AttributeStatement` (section 6.6, section
    12: values as text, without `xsi:type`) and completed the login. No mapper of the broker reads the two attributes,
    so the measure is that Keycloak's parser accepts them, not that it maps them.
20. **The assertion signed, the response not** (`SignedParts::Assertion`, the writer's default), under the broker's
    default `wantAssertionsSigned=true`; the model's times to the second under `allowedClockSkew=0`; its IDs, `_` and 40
    hexadecimal digits; a persistent `NameID` that became the username `model-alice`.
21. **A signature by another key is refused, both ways** (the two controls): the broker answers "Invalid signature in
    response from identity provider.", realm `idp` "Invalid requester", HTTP 400 each. The logins above are therefore
    proofs of the model's signatures under the certificates Keycloak imported, not of Keycloak's leniency.
22. **The model's signed metadata**: both importers accept a document whose first child is a `ds:Signature`; whether
    they verify it is not established here (neither is given a key to verify it with).
23. **The model's requests without `KeyInfo`**: realm `idp` verifies the `AuthnRequest` and the `LogoutRequest` under
    the client's certificate alone, as M-3 has the model do.

**What the model accepted from Keycloak, with what it reads.**

24. **The broker's `AuthnRequest`**: `AttributeConsumingServiceIndex="0"`, not read (6.2 step 5); its assertion
    consumer service resolved to the HTTP-POST one by its URL (M-9), `index="1"`.
25. **The broker's `LogoutRequest`**: no `NotOnOrAfter`, which 6.3 reads only when present.
26. **Realm `idp`'s response to the model**: as the first phase's, `SignatureCoverage::Response`, six `Role`
    attributes kept as six `Attribute` (6.1 step 11). The request's `NameIDPolicy` decides the format over the client's
    `saml_name_id_format=username`, which is not forced.

**Observations, no rule touched.**

27. **`KeyName`**: realm `idp`'s signatures carry a `KeyName` next to the certificate, the broker's do not, while the
    broker's metadata carries one; the model reads neither (M-3, D-7).
28. **A re-run of the exchange** on a live container needs the user `model-alice` deleted from realm `sp`: deleting an
    identity provider deletes its links and keeps the users, and the first broker login would then ask to link an
    existing account. The script does it.
