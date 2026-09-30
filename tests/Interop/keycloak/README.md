# Keycloak, the second interoperability target

Story #14, sections 9.4 and 9.5 of `spec/model.md`: Keycloak as an identity provider (realm `idp`) and as a service
provider (realm `sp`, whose SAML identity provider `idp` brokers the login to realm `idp`), in one container, run by
hand, never in the CI and never a dependency of the package. It reinforces the judge of 9.5 (SimpleSAMLphp) and is
not a condition of it. This phase builds the installation and captures what Keycloak writes; posting the model's own
documents into Keycloak waits for the writers (stories #9 and #10).

## Versions

| | |
|---|---|
| Keycloak | `quay.io/keycloak/keycloak:26.7.4`, manifest `sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c`, published on 16 September 2026 |
| How the tag was chosen | On 30 September 2026, the highest `x.y.z` tag of the registry, whose manifest is also the one of `latest` (`nightly` is not a release): `curl -s 'https://quay.io/api/v1/repository/keycloak/keycloak/tag/?limit=100&onlyActiveTags=true' \| jq -r '.tags[] \| "\(.name) \(.manifest_digest) \(.last_modified)"' \| sort -V` |
| Mode | `start-dev`: HTTP, the H2 database inside the container, the realms imported at startup from `realms/` |
| Port | 8180 on the host and in the container (8081 and 8082 are SimpleSAMLphp's, story #11) |
| Machine of the capture | macOS 26 (Darwin 25.6), Docker 29.8.1, Docker Compose 5.5.1, GNU bash 3.2.57, curl 8.7.1, perl 5.34.1 |

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
  `entityId=<realm URL>`, `sendIdTokenOnLogout=true`, `allowedClockSkew=0`, `attributeConsumingServiceIndex=0`; the
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
