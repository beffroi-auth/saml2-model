<?php

declare(strict_types=1);

/*
 * Plays the model against the Keycloak of compose.yaml, both ways (spec/model.md sections 9.4 and 9.5; story #14),
 * with the package of this repository and the test keys of tests/Fixture/keys/:
 *
 * 1. the model's two metadata, written by MetadataWriter and signed, given to Keycloak's own importers: realm sp's
 *    identity provider "model" from import-config, realm idp's SAML client from client-description-converter;
 * 2. two controls, each refused: a response the broker's trusted key did not sign, an AuthnRequest the client's key
 *    did not sign;
 * 3. the model as an identity provider, realm sp's broker in front: its AuthnRequest validated, the model's response
 *    posted to the broker, the login completed at the client "capture"; then the broker's LogoutRequest validated and
 *    the model's LogoutResponse posted back;
 * 4. the model as a service provider, realm idp in front: the model's AuthnRequest posted to realm idp, alice logged
 *    in, realm idp's response validated; then the model's LogoutRequest posted and realm idp's LogoutResponse
 *    validated.
 *
 * Every message travels over HTTP-POST, base64 in a form field, written here and not in saml2-bindings (section 9.5);
 * the browser is curl, one cookie jar per direction, following no redirect by itself. What Keycloak wrote is kept
 * byte for byte as decoded, keycloak-<version>-exchange-<idp|broker>-<document>-<YYYY-MM-DD>.xml in the output
 * directory; what the model wrote goes to the work directory, for xmlsec1. Run in the phpqa image, inside the network
 * namespace of the Keycloak container so that localhost:8180 names Keycloak as in every URL it builds, from the root
 * of the repository (castor keycloak does it):
 *   docker run --rm --network container:$(docker compose -f tests/Interop/keycloak/compose.yaml ps -q keycloak) \
 *       -v "$PWD:/project" -w /project ghcr.io/spomky-labs/phpqa:8.5 php tests/Interop/keycloak/exchange.php \
 *       [output directory, default tests/Fixture/real] [work directory, default tmp-phpqa/keycloak/model]
 */

require __DIR__ . '/../../../vendor/autoload.php';

use Beffroi\Saml2\Model\Assertion\Assertion;
use Beffroi\Saml2\Model\Assertion\Attribute;
use Beffroi\Saml2\Model\Assertion\AttributeNameFormat;
use Beffroi\Saml2\Model\Assertion\AuthnStatement;
use Beffroi\Saml2\Model\Assertion\Conditions;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Assertion\SubjectConfirmation;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Protocol\LogoutRequest;
use Beffroi\Saml2\Model\Protocol\LogoutResponse;
use Beffroi\Saml2\Model\Protocol\NameIdPolicy;
use Beffroi\Saml2\Model\Protocol\Response;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Protocol\UnverifiedAuthnRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutResponse;
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\LogoutRequestValidator;
use Beffroi\Saml2\Model\Validation\LogoutResponseValidator;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Saml2\Model\Writing\AuthnRequestWriter;
use Beffroi\Saml2\Model\Writing\LogoutRequestWriter;
use Beffroi\Saml2\Model\Writing\LogoutResponseWriter;
use Beffroi\Saml2\Model\Writing\MetadataWriter;
use Beffroi\Saml2\Model\Writing\ResponseWriter;
use Beffroi\Saml2\Model\Writing\SignedParts;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Dsig\PrivateKey;
use Psr\Clock\ClockInterface;

const BASE = 'http://localhost:8180';
const CLIENT_REDIRECT = BASE . '/capture';
// The disposable test user of realms/idp.json.
const USERNAME = 'alice';
const PASSWORD = 'alice';

// The model's two roles. Nothing answers at these URLs: the script reads what Keycloak sends there and answers.
const MODEL_IDP = 'https://idp.saml2-model.test/metadata';
const MODEL_SSO = 'https://idp.saml2-model.test/sso';
const MODEL_IDP_SLO = 'https://idp.saml2-model.test/slo';
const MODEL_SP = 'https://sp.saml2-model.test/metadata';
const MODEL_ACS = 'https://sp.saml2-model.test/acs';
const MODEL_SP_SLO = 'https://sp.saml2-model.test/slo';
// The subject the model's identity provider asserts: a name no login of realms/idp.json can give realm sp's users.
const MODEL_SUBJECT = 'model-alice';

// Realm sp's identity provider for the model, and the settings of the admin console's form that import-config does
// not return (SamlGeneralSettings-*.js of Keycloak 26.7.4, as README.md reads them): what an administrator who
// imports the model's metadata in the console gets.
const BROKER_ALIAS = 'model';
const CONSOLE_DEFAULTS = [
    'entityId' => BASE . '/realms/sp',
    'wantAssertionsSigned' => 'true',
    'nameIDPolicyFormat' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    'principalType' => 'SUBJECT',
    'allowCreate' => 'true',
    'allowedClockSkew' => '0',
    'attributeConsumingServiceIndex' => '0',
];
const FIRST_BROKER_LOGIN = 'first broker login without review profile';

$root = dirname(__DIR__, 3);
$out = $argv[1] ?? $root . '/tests/Fixture/real';
$work = $argv[2] ?? $root . '/tmp-phpqa/keycloak/model';
preg_match('~image: quay\.io/keycloak/keycloak:([0-9.]+)~', (string) file_get_contents(__DIR__ . '/compose.yaml'), $match)
    || fail('No Keycloak version in compose.yaml.');
$version = $match[1];
$day = gmdate('Y-m-d');
foreach ([$out, $work] as $directory) {
    is_dir($directory) || mkdir($directory, 0o777, true) || fail("Cannot create $directory.");
}

$clock = new class implements ClockInterface {
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }
};
$loader = SamlLoader::create();
$serializer = new Serializer();
$idpSigning = new Signing(PrivateKey::fromPem(fixtureKey('idp-signing-key.pem')));
$spSigning = new Signing(PrivateKey::fromPem(fixtureKey('sp-signing-key.pem')));
$metadataReader = new MetadataReader($loader, $clock);

waitForKeycloak();
echo "Keycloak $version on " . BASE . ", exchange of $day, Keycloak's documents into $out, the model's into $work\n";

/*
 * 1. The model's metadata, and Keycloak configured from them.
 */
echo "The model's metadata, given to Keycloak\n";
$modelIdp = new IdentityProvider(
    MODEL_IDP,
    [certificate('idp-signing-certificate.pem')],
    [],
    [new Endpoint(Binding::HttpPost, MODEL_SSO)],
    [new Endpoint(Binding::HttpPost, MODEL_IDP_SLO)],
    [NameIdFormat::Persistent],
    wantAuthnRequestsSigned: true,
);
$modelSp = new ServiceProvider(
    MODEL_SP,
    [certificate('sp-signing-certificate.pem')],
    [],
    new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, MODEL_ACS, 0, true)]),
    [new Endpoint(Binding::HttpPost, MODEL_SP_SLO)],
    [],
    authnRequestsSigned: true,
    wantAssertionsSigned: false,
);
$writer = new MetadataWriter();
$idpMetadata = model('idp-metadata', $writer->write(new EntityDescriptor(MODEL_IDP, identityProvider: $modelIdp), $idpSigning));
$spMetadata = model('sp-metadata', $writer->write(new EntityDescriptor(MODEL_SP, serviceProvider: $modelSp), $spSigning));

$admin = adminToken();
$existing = admin($admin, 'GET', '/admin/realms/sp/identity-provider/instances/' . BROKER_ALIAS, expect: [200, 404]);
if ($existing['status'] === 200) {
    admin($admin, 'DELETE', '/admin/realms/sp/identity-provider/instances/' . BROKER_ALIAS, expect: [204]);
}
// The user the model's subject became in realm sp on an earlier run, whose link the deletion above removed: left,
// the first broker login would ask to link it instead of creating it.
foreach (json(admin($admin, 'GET', '/admin/realms/sp/users?exact=true&username=' . rawurlencode(MODEL_SUBJECT))['body']) as $user) {
    admin($admin, 'DELETE', '/admin/realms/sp/users/' . $user['id'], expect: [204]);
}
$imported = json(admin($admin, 'POST', '/admin/realms/sp/identity-provider/import-config', multipart: [
    'providerId' => 'saml',
    'file' => new CURLStringFile($idpMetadata, 'idp-metadata.xml', 'application/xml'),
])['body']);
admin($admin, 'POST', '/admin/realms/sp/identity-provider/instances', json: [
    'alias' => BROKER_ALIAS,
    'providerId' => 'saml',
    'enabled' => true,
    'firstBrokerLoginFlowAlias' => FIRST_BROKER_LOGIN,
    'config' => array_merge(CONSOLE_DEFAULTS, $imported),
], expect: [201]);
$broker = json(admin($admin, 'GET', '/admin/realms/sp/identity-provider/instances/' . BROKER_ALIAS)['body']);
file_put_contents("$work/keycloak-sp-identity-provider-" . BROKER_ALIAS . '.json', pretty($broker));
ksort($imported);
echo '  realm sp, identity provider ' . BROKER_ALIAS . ' from import-config: ' . settings($imported) . "\n";

$clients = json(admin($admin, 'GET', '/admin/realms/idp/clients?clientId=' . rawurlencode(MODEL_SP))['body']);
foreach ($clients as $client) {
    admin($admin, 'DELETE', '/admin/realms/idp/clients/' . $client['id'], expect: [204]);
}
$description = json(admin($admin, 'POST', '/admin/realms/idp/client-description-converter', raw: $spMetadata, type: 'application/xml')['body']);
admin($admin, 'POST', '/admin/realms/idp/clients', json: $description, expect: [201]);
$client = json(admin($admin, 'GET', '/admin/realms/idp/clients?clientId=' . rawurlencode(MODEL_SP))['body'])[0];
file_put_contents("$work/keycloak-idp-client.json", pretty($client));
$converted = $description['attributes'];
ksort($converted);
echo '  realm idp, client ' . MODEL_SP . ' from client-description-converter: ' . settings($converted) . "\n";

echo "Keycloak's metadata\n";
$idpDescriptor = keep('idp', 'metadata', get(BASE . '/realms/idp/protocol/saml/descriptor'), 'GET /realms/idp/protocol/saml/descriptor');
$brokerDescriptor = keep('broker', 'metadata', get(BASE . '/realms/sp/broker/' . BROKER_ALIAS . '/endpoint/descriptor'), 'GET /realms/sp/broker/' . BROKER_ALIAS . '/endpoint/descriptor');
$realmIdp = $metadataReader->readTrusted($loader->load($idpDescriptor))->identityProvider ?? fail('Realm idp publishes no identity provider.');
$brokerSp = $metadataReader->readTrusted($loader->load($brokerDescriptor))->serviceProvider ?? fail('The broker publishes no service provider.');
$sso = endpoint($realmIdp->singleSignOnServices);
echo '  read by MetadataReader::readTrusted(): realm idp, ' . count($realmIdp->signingCertificates) . ' signing certificate; the broker, '
    . count($brokerSp->signingCertificates) . ' signing certificate, AuthnRequestsSigned ' . flag($brokerSp->authnRequestsSigned)
    . ', WantAssertionsSigned ' . flag($brokerSp->wantAssertionsSigned) . "\n";

/*
 * 2. Two controls first, each in a browser of its own, so that the logins below prove something: Keycloak refuses a
 *    signature by a key it was not given, whichever of the model's test keys signs.
 */
echo "Controls: a signature by the other test key\n";
$control = new Browser();
[$action, $fields] = samlForm($control->followRedirects($control->get(brokerLogin())), 'SAMLRequest');
$controlRequest = new AuthnRequestValidator($loader, $clock)->validate(
    UnverifiedAuthnRequest::of($loader->load(base64_decode($fields['SAMLRequest'], true) ?: fail('SAMLRequest is not base64.'))),
    $brokerSp,
    $modelIdp,
    MODEL_SSO,
)->request;
$acs = $brokerSp->assertionConsumerServices->default()->location;
$forged = $serializer->serialize(new ResponseWriter()->write(modelResponse($controlRequest->id, $acs, $brokerSp->entityId, second($clock->now())), $spSigning));
refused($control->post($acs, ['SAMLResponse' => base64_encode($forged), 'RelayState' => $fields['RelayState'] ?? '']), 'the broker, a response whose assertion the service provider test key signed');
$control = new Browser();
$forged = $serializer->serialize(new AuthnRequestWriter()->write(modelRequest($sso, second($clock->now())), $idpSigning));
refused($control->post($sso, ['SAMLRequest' => base64_encode($forged)]), 'realm idp, an AuthnRequest the identity provider test key signed');

/*
 * 3. The model as an identity provider, realm sp's broker in front.
 */
echo "The model as identity provider, realm sp's broker in front\n";
$browser = new Browser();
[$action, $fields] = samlForm($browser->followRedirects($browser->get(brokerLogin())), 'SAMLRequest');
$action === MODEL_SSO || fail("The broker posted its AuthnRequest to $action.");
$bytes = keep('broker', 'authn-request', base64_decode($fields['SAMLRequest'], true) ?: fail('SAMLRequest is not base64.'), 'HTTP-POST to ' . $action . ', fields ' . implode(' ', array_keys($fields)));
$accepted = new AuthnRequestValidator($loader, $clock)->validate(UnverifiedAuthnRequest::of($loader->load($bytes)), $brokerSp, $modelIdp, MODEL_SSO);
$request = $accepted->request;
echo "  accepted by AuthnRequestValidator::validate(): {$accepted->authentication->name}, ID {$request->id}, assertion consumer service "
    . "{$accepted->assertionConsumerService->location} index {$accepted->assertionConsumerService->index}, ProtocolBinding "
    . ($request->protocolBinding ?? 'none') . ', NameIDPolicy ' . ($request->nameIdPolicy->format ?? 'none') . "\n";
$acs = $accepted->assertionConsumerService->location;
$response = modelResponse($request->id, $acs, $brokerSp->entityId, second($clock->now()));
$written = model('idp-response', new ResponseWriter()->write($response, $idpSigning, SignedParts::Assertion));
echo "  the model's response {$response->id}, its assertion signed (SignedParts::Assertion), posted to $acs\n";
$page = $browser->followRedirects($browser->post($acs, ['SAMLResponse' => base64_encode($written), 'RelayState' => $fields['RelayState'] ?? '']), CLIENT_REDIRECT);
$code = queryParameter($page['location'], 'code') ?? fail('No authorization code at the client redirect.');
$tokens = json($browser->post(BASE . '/realms/sp/protocol/openid-connect/token', [
    'grant_type' => 'authorization_code',
    'code' => $code,
    'redirect_uri' => CLIENT_REDIRECT,
    'client_id' => 'capture',
])['body']);
$idToken = $tokens['id_token'] ?? fail('No id_token.');
$claims = json(base64_decode(strtr(explode('.', $idToken)[1], '-_', '+/'), true) ?: '{}');
echo "  logged in at the client of realm sp: preferred_username {$claims['preferred_username']}\n";

$page = $browser->followRedirects($browser->get(BASE . '/realms/sp/protocol/openid-connect/logout?' . http_build_query([
    'id_token_hint' => $idToken,
    'post_logout_redirect_uri' => CLIENT_REDIRECT,
])));
[$action, $fields] = samlForm($page, 'SAMLRequest');
$action === MODEL_IDP_SLO || fail("The broker posted its LogoutRequest to $action.");
$bytes = keep('broker', 'logout-request', base64_decode($fields['SAMLRequest'], true) ?: fail('SAMLRequest is not base64.'), 'HTTP-POST to ' . $action . ', fields ' . implode(' ', array_keys($fields)));
$acceptedLogout = new LogoutRequestValidator($loader, $clock)->validate(UnverifiedLogoutRequest::of($loader->load($bytes)), $brokerSp, $modelIdp, MODEL_IDP_SLO);
$logoutRequest = $acceptedLogout->request;
echo "  accepted by LogoutRequestValidator::validate(): {$acceptedLogout->authentication->name}, ID {$logoutRequest->id}, NameID "
    . "{$logoutRequest->nameId->value}, SessionIndex " . implode(' ', $logoutRequest->sessionIndexes) . "\n";
$brokerSlo = endpoint($brokerSp->singleLogoutServices);
$logoutResponse = new LogoutResponse(
    SamlId::generate(),
    second($clock->now()),
    new Issuer(MODEL_IDP),
    $brokerSlo,
    $logoutRequest->id,
    new Status(StatusCode::Success),
);
$written = model('idp-logout-response', new LogoutResponseWriter()->write($logoutResponse, $idpSigning));
echo "  the model's LogoutResponse {$logoutResponse->id}, signed, posted to $brokerSlo\n";
$browser->followRedirects($browser->post($brokerSlo, ['SAMLResponse' => base64_encode($written), 'RelayState' => $fields['RelayState'] ?? '']), CLIENT_REDIRECT);
echo "  logged out, back at the client of realm sp\n";

/*
 * 4. The model as a service provider, realm idp in front.
 */
echo "The model as service provider, realm idp in front\n";
$browser = new Browser();
$authnRequest = modelRequest($sso, second($clock->now()));
$written = model('sp-authn-request', new AuthnRequestWriter()->write($authnRequest, $spSigning));
echo "  the model's AuthnRequest {$authnRequest->id}, signed, posted to $sso\n";
$page = $browser->followRedirects($browser->post($sso, ['SAMLRequest' => base64_encode($written), 'RelayState' => 'model-relay-state']));
$login = formAction($page['body'], 'kc-form-login') ?? fail("No login form at realm idp (HTTP {$page['status']}).");
$page = $browser->followRedirects($browser->post($login, ['username' => USERNAME, 'password' => PASSWORD, 'credentialId' => '']));
[$action, $fields] = samlForm($page, 'SAMLResponse');
$action === MODEL_ACS || fail("Realm idp posted its response to $action.");
($fields['RelayState'] ?? null) === 'model-relay-state' || fail('Realm idp did not return the RelayState.');
$bytes = keep('idp', 'response', base64_decode($fields['SAMLResponse'], true) ?: fail('SAMLResponse is not base64.'), 'HTTP-POST to ' . $action . ', fields ' . implode(' ', array_keys($fields)));
$acceptedAssertion = new ResponseValidator($loader, $clock, new InMemoryReplayGuard())->validate(
    UnverifiedResponse::of($loader->load($bytes)),
    $realmIdp,
    ExpectedResponse::toRequest($authnRequest->id, MODEL_ACS, MODEL_SP),
);
$assertion = $acceptedAssertion->assertion;
echo "  accepted by ResponseValidator::validate(): SignatureCoverage::{$acceptedAssertion->coverage->name}, response "
    . "{$acceptedAssertion->responseId}, NameID {$assertion->nameId->value} ({$assertion->nameId->format->name}), SessionIndex "
    . ($assertion->authnStatement->sessionIndex ?? 'none') . ', ' . count($assertion->attributes) . " attributes\n";

$slo = endpoint($realmIdp->singleLogoutServices);
$logoutRequest = new LogoutRequest(
    SamlId::generate(),
    second($clock->now()),
    new Issuer(MODEL_SP),
    $slo,
    null,
    $assertion->nameId,
    $assertion->authnStatement->sessionIndex === null ? [] : [$assertion->authnStatement->sessionIndex],
);
$written = model('sp-logout-request', new LogoutRequestWriter()->write($logoutRequest, $spSigning));
echo "  the model's LogoutRequest {$logoutRequest->id}, signed, posted to $slo\n";
$page = $browser->followRedirects($browser->post($slo, ['SAMLRequest' => base64_encode($written), 'RelayState' => 'model-relay-state']));
[$action, $fields] = samlForm($page, 'SAMLResponse');
$action === MODEL_SP_SLO || fail("Realm idp posted its LogoutResponse to $action.");
$bytes = keep('idp', 'logout-response', base64_decode($fields['SAMLResponse'], true) ?: fail('SAMLResponse is not base64.'), 'HTTP-POST to ' . $action . ', fields ' . implode(' ', array_keys($fields)));
$acceptedLogoutResponse = new LogoutResponseValidator($loader, $clock)->validate(
    UnverifiedLogoutResponse::of($loader->load($bytes)),
    $realmIdp,
    $modelSp,
    MODEL_SP_SLO,
    $logoutRequest->id,
);
echo "  accepted by LogoutResponseValidator::validate(): {$acceptedLogoutResponse->authentication->name}, ID "
    . "{$acceptedLogoutResponse->response->id}, status {$acceptedLogoutResponse->response->status->code->name}\n";
echo "Both directions completed.\n";

/**
 * A minimal browser: one curl handle, whose cookie engine is the jar of one direction, following no redirect by
 * itself.
 */
final class Browser
{
    private CurlHandle $curl;

    public function __construct()
    {
        $this->curl = curl_init();
        curl_setopt_array($this->curl, [
            CURLOPT_COOKIEFILE => '',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => 30,
        ]);
    }

    /**
     * @return array{status: int, location: ?string, body: string, url: string}
     */
    public function get(string $url): array
    {
        curl_setopt($this->curl, CURLOPT_HTTPGET, true);

        return $this->send($url);
    }

    /**
     * @param array<string, string> $fields
     *
     * @return array{status: int, location: ?string, body: string, url: string}
     */
    public function post(string $url, array $fields): array
    {
        curl_setopt($this->curl, CURLOPT_POST, true);
        curl_setopt($this->curl, CURLOPT_POSTFIELDS, http_build_query($fields));

        return $this->send($url);
    }

    /**
     * Follows the redirects of $page until one goes to $until, or, without $until, until a page that is not a
     * redirect.
     *
     * @param array{status: int, location: ?string, body: string, url: string} $page
     *
     * @return array{status: int, location: ?string, body: string, url: string}
     */
    public function followRedirects(array $page, ?string $until = null): array
    {
        for ($hops = 0; $hops <= 10; $hops++) {
            if ($page['location'] === null) {
                $until === null || fail("HTTP {$page['status']} at {$page['url']} where a redirect to $until was expected: " . text($page['body']));

                return $page;
            }
            if ($until !== null && str_starts_with($page['location'], $until)) {
                return $page;
            }
            $page = $this->get($page['location']);
        }
        fail('More than 10 redirects.');
    }

    /**
     * @return array{status: int, location: ?string, body: string, url: string}
     */
    private function send(string $url): array
    {
        $location = null;
        curl_setopt($this->curl, CURLOPT_URL, $url);
        curl_setopt($this->curl, CURLOPT_HEADERFUNCTION, static function (CurlHandle $curl, string $header) use (&$location): int {
            if (preg_match('~^location:\s*(.+?)\s*$~i', $header, $match) === 1) {
                $location = $match[1];
            }

            return strlen($header);
        });
        $body = curl_exec($this->curl);
        is_string($body) || fail("$url: " . curl_error($this->curl));
        $status = curl_getinfo($this->curl, CURLINFO_RESPONSE_CODE);
        if ($location !== null && ! str_contains($location, '://')) {
            $location = BASE . $location;
        }

        return ['status' => $status, 'location' => $location, 'body' => $body, 'url' => $url];
    }
}

/**
 * The model's identity provider's answer to the request $requestId: the subject MODEL_SUBJECT, persistent, a bearer
 * window and conditions of 300 s from $now, which realm sp's broker checks with no skew (allowedClockSkew=0), two
 * attributes whose values carry no xsi:type (section 6.6).
 */
function modelResponse(string $requestId, string $acs, string $audience, DateTimeImmutable $now): Response
{
    return new Response(
        SamlId::generate(),
        $now,
        new Issuer(MODEL_IDP),
        $acs,
        $requestId,
        new Status(StatusCode::Success),
        new Assertion(
            SamlId::generate(),
            $now,
            new Issuer(MODEL_IDP),
            new NameId(MODEL_SUBJECT, NameIdFormat::Persistent),
            new SubjectConfirmation($acs, $now->modify('+300 seconds'), $requestId, null),
            new Conditions($now, $now->modify('+300 seconds'), [[$audience]], false),
            new AuthnStatement($now, SamlId::generate(), null, 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'),
            [
                new Attribute('email', AttributeNameFormat::Basic, null, ['alice@saml2-model.test']),
                new Attribute('Role', AttributeNameFormat::Basic, null, ['member', 'reader']),
            ],
        ),
    );
}

/**
 * The model's service provider's request to realm idp, a persistent identifier asked, as Keycloak's broker asks.
 */
function modelRequest(string $sso, DateTimeImmutable $now): AuthnRequest
{
    return new AuthnRequest(
        SamlId::generate(),
        $now,
        new Issuer(MODEL_SP),
        $sso,
        MODEL_ACS,
        null,
        Binding::HttpPost->value,
        new NameIdPolicy(NameIdFormat::Persistent->value, null, true),
    );
}

/**
 * The start of a login at the client "capture" of realm sp, sent to the model by its broker.
 */
function brokerLogin(): string
{
    return BASE . '/realms/sp/protocol/openid-connect/auth?' . http_build_query([
        'client_id' => 'capture',
        'response_type' => 'code',
        'scope' => 'openid',
        'redirect_uri' => CLIENT_REDIRECT,
        'kc_idp_hint' => BROKER_ALIAS,
    ]);
}

/**
 * A control: Keycloak answered with an error, neither a redirect nor a form going on.
 *
 * @param array{status: int, location: ?string, body: string, url: string} $page
 */
function refused(array $page, string $what): void
{
    ($page['status'] >= 400 && $page['location'] === null && formAction($page['body'], 'saml-post-binding') === null)
        || fail("Not refused: $what (HTTP {$page['status']}" . ($page['location'] === null ? '' : ", Location {$page['location']}") . ').');
    echo "  refused by $what: HTTP {$page['status']}, \"" . text($page['body']) . "\"\n";
}

/**
 * The action and the hidden fields of the auto-submitted form Keycloak writes for the HTTP-POST binding, the
 * character references resolved.
 *
 * @param array{status: int, location: ?string, body: string, url: string} $page
 *
 * @return array{0: string, 1: array<string, string>}
 */
function samlForm(array $page, string $message): array
{
    $action = formAction($page['body'], 'saml-post-binding')
        ?? fail("No HTTP-POST form carrying $message (HTTP {$page['status']} at {$page['url']}): " . text($page['body']));
    preg_match_all('~<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"~i', $page['body'], $inputs, PREG_SET_ORDER);
    $fields = [];
    foreach ($inputs as [, $name, $value]) {
        $fields[$name] = html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
    isset($fields[$message]) || fail("The form to $action carries no $message.");

    return [$action, $fields];
}

function formAction(string $html, string $idOrName): ?string
{
    if (preg_match('~<form\b[^>]*\b(?:id|name)="' . preg_quote($idOrName, '~') . '"[^>]*>~i', $html, $form) !== 1) {
        return null;
    }
    if (preg_match('~\baction="([^"]*)"~i', $form[0], $action) !== 1) {
        return null;
    }

    return html_entity_decode($action[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

function queryParameter(?string $url, string $name): ?string
{
    parse_str((string) parse_url((string) $url, PHP_URL_QUERY), $query);
    $value = $query[$name] ?? null;

    return is_string($value) ? $value : null;
}

function waitForKeycloak(): void
{
    for ($i = 0; $i < 90; $i++) {
        $curl = curl_init(BASE . '/realms/sp/broker/idp/endpoint/descriptor');
        curl_setopt_array($curl, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5]);
        curl_exec($curl);
        if (curl_getinfo($curl, CURLINFO_RESPONSE_CODE) === 200) {
            return;
        }
        sleep(2);
    }
    fail('Keycloak did not answer on port 8180 within 180 s.');
}

function get(string $url): string
{
    $page = new Browser()->get($url);
    $page['status'] === 200 || fail("GET $url: HTTP {$page['status']}.");

    return $page['body'];
}

/**
 * The admin REST API of Keycloak, with the disposable administrator of compose.yaml.
 */
function adminToken(): string
{
    $curl = curl_init(BASE . '/realms/master/protocol/openid-connect/token');
    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POSTFIELDS => http_build_query(['grant_type' => 'password', 'client_id' => 'admin-cli', 'username' => 'admin', 'password' => 'admin']),
    ]);

    return json((string) curl_exec($curl))['access_token'] ?? fail('No admin token.');
}

/**
 * @param array<string, mixed>|list<mixed>|null $json
 * @param array<string, string|CURLStringFile>|null $multipart
 * @param list<int> $expect
 *
 * @return array{status: int, body: string}
 */
function admin(string $token, string $method, string $path, ?array $json = null, ?array $multipart = null, ?string $raw = null, string $type = 'application/json', array $expect = [200]): array
{
    $curl = curl_init(BASE . $path);
    $headers = ['Authorization: Bearer ' . $token];
    curl_setopt_array($curl, [CURLOPT_RETURNTRANSFER => true, CURLOPT_CUSTOMREQUEST => $method]);
    if ($json !== null) {
        $raw = json_encode($json, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
    if ($raw !== null) {
        $headers[] = 'Content-Type: ' . $type;
        curl_setopt($curl, CURLOPT_POSTFIELDS, $raw);
    }
    if ($multipart !== null) {
        curl_setopt($curl, CURLOPT_POSTFIELDS, $multipart);
    }
    curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
    $body = (string) curl_exec($curl);
    $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    in_array($status, $expect, true) || fail("$method $path: HTTP $status " . text($body));

    return ['status' => $status, 'body' => $body];
}

/**
 * @return array<mixed>
 */
function json(string $text): array
{
    $value = json_decode($text, true, flags: JSON_THROW_ON_ERROR);
    is_array($value) || fail('Not a JSON object: ' . text($text));

    return $value;
}

/**
 * @param array<mixed> $value
 */
function pretty(array $value): string
{
    return json_encode($value, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
}

/**
 * @param array<string, string> $settings
 */
function settings(array $settings): string
{
    $shown = [];
    foreach ($settings as $name => $value) {
        $shown[] = $name . '=' . (strlen($value) > 64 ? '<' . strlen($value) . ' characters>' : $value);
    }

    return implode(', ', $shown);
}

/**
 * A document Keycloak wrote, kept byte for byte as decoded.
 */
function keep(string $producer, string $document, string $bytes, string $how): string
{
    global $out, $version, $day;
    $file = "$out/keycloak-$version-exchange-$producer-$document-$day.xml";
    file_put_contents($file, $bytes) === strlen($bytes) || fail("Cannot write $file.");
    echo '  ' . basename($file) . ": $how\n";

    return $bytes;
}

/**
 * A document the model wrote, serialized by Core's Serializer, kept for xmlsec1.
 */
function model(string $document, Document $written): string
{
    global $work, $serializer;
    $bytes = $serializer->serialize($written);
    file_put_contents("$work/model-$document.xml", $bytes) === strlen($bytes) || fail("Cannot write $work/model-$document.xml.");

    return $bytes;
}

/**
 * The location of the first endpoint on HTTP-POST.
 *
 * @param list<Endpoint> $endpoints
 */
function endpoint(array $endpoints): string
{
    foreach ($endpoints as $endpoint) {
        if ($endpoint->binding === Binding::HttpPost) {
            return $endpoint->location;
        }
    }
    fail('No endpoint on HTTP-POST.');
}

function second(DateTimeImmutable $time): DateTimeImmutable
{
    return $time->setTime((int) $time->format('H'), (int) $time->format('i'), (int) $time->format('s'));
}

function fixtureKey(string $file): string
{
    return (string) file_get_contents(dirname(__DIR__, 2) . '/Fixture/keys/' . $file);
}

function certificate(string $file): string
{
    return (string) preg_replace('~-----[A-Z ]+-----|\s+~', '', fixtureKey($file));
}

function flag(bool $value): string
{
    return $value ? 'true' : 'false';
}

/**
 * What a page says: the message of Keycloak's error page when it is one, else its text without scripts and styles.
 */
function text(string $body): string
{
    if (preg_match('~<div id="kc-error-message">\s*<p class="instruction">(.*?)</p>~s', $body, $message) === 1) {
        return html_entity_decode(trim($message[1]), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
    $body = (string) preg_replace('~<(script|style)\b.*?</\1>~si', '', $body);

    return substr(trim((string) preg_replace('~\s+~', ' ', html_entity_decode(strip_tags($body), ENT_QUOTES | ENT_HTML5, 'UTF-8'))), 0, 300);
}

function fail(string $message): never
{
    fwrite(STDERR, "exchange: $message\n");
    exit(1);
}
