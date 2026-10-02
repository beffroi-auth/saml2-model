<?php

declare(strict_types=1);

/*
 * The exchange of phase 2 of story #11 (README.md of this directory, section 6): the model and the SimpleSAMLphp
 * installation of installation/, both ways, as an identity provider and as a service provider, login and logout, on
 * the running installation, with the package of the repository (its vendor/autoload.php), the test keys of
 * tests/Fixture/keys/ and the live clock.
 *
 * The script is the model's side of the wire: the browser, which carries every message with one cookie jar per
 * direction, and the HTTP layer of the model's two roles, which nothing provides yet. It stands in for saml2-bindings
 * (spec/model.md section 6.8): it decodes what HTTP-Redirect carries after verifying the signature over its query
 * string with Verifier::verifyDetached() under the keys of the sender's metadata, and posts what the writers wrote
 * with the form encoding of HTTP-POST, base64 in a form field. None of it is the package's: saml2-bindings writes its
 * own.
 *
 * The model's metadata, both roles, and every document the model writes go to written/, from which the installation
 * reads the model's metadata and which castor simplesamlphp hands to verify.php and xmlsec1 afterwards; what
 * SimpleSAMLphp sends goes to received/, or to tests/Fixture/real/ with --keep, named with its version and the date,
 * as phase 1 names its captures. Four probes follow the directions: a document of the model changed after signing,
 * posted where its genuine twin was accepted, which SimpleSAMLphp must refuse, so that its acceptance of the genuine
 * one proves a signature it verified (findings F-3 and F-9 of the README). One line per step; the exit status is 1
 * when a step fails.
 *
 * From the root of the repository, the installation up in its third configuration (castor simplesamlphp runs it all):
 *   docker run --rm --network saml2-model-simplesamlphp_default \
 *       -e EXCHANGE_CONNECT_TO=localhost:8081:idp:80,localhost:8082:sp:80 -v "$PWD:/project" -w /project \
 *       ghcr.io/spomky-labs/phpqa:8.5 php tests/Interop/simplesamlphp/exchange.php [--keep]
 */

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
use Beffroi\Saml2\Model\Validation\AcceptedAssertion;
use Beffroi\Saml2\Model\Validation\AcceptedAuthnRequest;
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
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\Verifier;
use Psr\Clock\ClockInterface;

require __DIR__ . '/../../../vendor/autoload.php';

const VERSION = '2.5.3.1';
const IDP = 'http://localhost:8081/simplesaml';
const SP = 'http://localhost:8082/simplesaml';
// The model's two roles: nothing listens on port 8083, the script is what answers there.
const MODEL = 'http://localhost:8083/model';

/**
 * The live clock, the one the model reads in the exchange: a replay of a captured document freezes it, in the suite.
 */
final class SystemClock implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }
}

/**
 * A browser with one cookie jar: one hop per call, never following a redirect by itself. EXCHANGE_CONNECT_TO pins
 * localhost:8081 and localhost:8082 to the containers, so that the Host header, every entity ID and every
 * Destination stay those the installation knows.
 */
final class Browser
{
    public int $status = 0;

    public ?string $location = null;

    public string $body = '';

    public string $url = '';

    private CurlHandle $curl;

    public function __construct()
    {
        $this->curl = curl_init();
        curl_setopt_array($this->curl, [
            CURLOPT_COOKIEFILE => '',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HEADERFUNCTION => function (CurlHandle $curl, string $header): int {
                if (preg_match('/^Location:\s*(\S+)\s*$/i', $header, $match) === 1) {
                    $this->location = $match[1];
                }

                return strlen($header);
            },
        ]);
        $connectTo = getenv('EXCHANGE_CONNECT_TO');
        if (is_string($connectTo) && $connectTo !== '') {
            curl_setopt($this->curl, CURLOPT_CONNECT_TO, explode(',', $connectTo));
        }
    }

    public function get(string $url): self
    {
        curl_setopt($this->curl, CURLOPT_HTTPGET, true);

        return $this->send($url);
    }

    /**
     * The HTTP-POST binding's form: application/x-www-form-urlencoded, each value a form field.
     *
     * @param array<string, string> $fields
     */
    public function post(string $url, array $fields): self
    {
        curl_setopt_array($this->curl, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => http_build_query($fields)]);

        return $this->send($url);
    }

    /**
     * The target of the redirect this answer is, or a failure naming what was expected.
     */
    public function redirect(string $expected): string
    {
        if (! in_array($this->status, [302, 303], true) || $this->location === null) {
            throw new RuntimeException(sprintf('expected %s, got HTTP %d at %s%s', $expected, $this->status, $this->url, $this->error()));
        }

        return $this->location;
    }

    /**
     * Follows the redirects, one hop at a time, while they stay under $prefix, as a browser would inside one party.
     */
    public function followWithin(string $prefix): self
    {
        while (in_array($this->status, [302, 303], true) && str_starts_with((string) $this->location, $prefix)) {
            $this->get((string) $this->location);
        }

        return $this;
    }

    /**
     * The value of a form field of the page, HTML entities decoded.
     */
    public function field(string $name): ?string
    {
        $pattern = '/<input[^>]*name="' . preg_quote($name, '/') . '"[^>]*value="([^"]*)"/';

        return preg_match($pattern, $this->body, $match) === 1 ? html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5) : null;
    }

    public function formAction(): ?string
    {
        return preg_match('/<form[^>]*action="([^"]*)"/', $this->body, $match) === 1
            ? html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5)
            : null;
    }

    /**
     * The exception SimpleSAMLphp's error page names ("Caused by:", shown since showerrors is true by default), when
     * the answer is one.
     */
    public function error(): string
    {
        if ($this->status < 400 || preg_match('/Caused by: ([^\n<]+)/', $this->body, $match) !== 1) {
            return '';
        }

        return ': ' . trim(html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5));
    }

    private function send(string $url): self
    {
        $this->location = null;
        curl_setopt($this->curl, CURLOPT_URL, $url);
        $body = curl_exec($this->curl);
        if (! is_string($body)) {
            throw new RuntimeException(sprintf('%s: %s', $url, curl_error($this->curl)));
        }
        $this->url = $url;
        $this->body = $body;
        $this->status = (int) curl_getinfo($this->curl, CURLINFO_RESPONSE_CODE);

        return $this;
    }
}

final class Exchange
{
    private const string TEST_USER = 'student';

    private const string TEST_PASSWORD = 'studentpass';

    /**
     * What the model's identity provider asserts: the attributes the service provider's session must then hold.
     *
     * @var array<string, list<string>>
     */
    private const array ATTRIBUTES = ['uid' => ['model-student'], 'eduPersonAffiliation' => ['member', 'student']];

    public readonly EntityDescriptor $identityProvider;

    public readonly EntityDescriptor $serviceProvider;

    private readonly ClockInterface $clock;

    private readonly string $today;

    public function __construct(
        private readonly string $written,
        private readonly string $received,
        private readonly string $keys,
    ) {
        $this->clock = new SystemClock();
        $this->today = $this->clock->now()->format('Y-m-d');
        $this->identityProvider = new EntityDescriptor(
            MODEL . '/idp',
            identityProvider: new IdentityProvider(
                MODEL . '/idp',
                [$this->certificate('idp')],
                [],
                [new Endpoint(Binding::HttpRedirect, MODEL . '/idp/sso')],
                [new Endpoint(Binding::HttpRedirect, MODEL . '/idp/slo')],
                [NameIdFormat::Transient],
                wantAuthnRequestsSigned: true,
            ),
        );
        $this->serviceProvider = new EntityDescriptor(
            MODEL . '/sp',
            serviceProvider: new ServiceProvider(
                MODEL . '/sp',
                [$this->certificate('sp')],
                [],
                new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, MODEL . '/sp/acs', 0, true)]),
                [new Endpoint(Binding::HttpPost, MODEL . '/sp/slo')],
                [NameIdFormat::Transient],
                authnRequestsSigned: true,
                wantAssertionsSigned: true,
            ),
        );
    }

    /**
     * Both metadata, written and signed by the model with the key of their role, where the installation reads them
     * (SimpleSAMLphp parses its metadata at every request).
     */
    public function writeMetadata(): void
    {
        foreach (['idp' => $this->identityProvider, 'sp' => $this->serviceProvider] as $role => $descriptor) {
            $this->write(sprintf('model-%s-metadata', $role), new MetadataWriter()->write($descriptor, $this->signing($role)));
        }
    }

    /**
     * The model as identity provider, SimpleSAMLphp's service provider for-model in front: its AuthnRequest, from its
     * HTTP-Redirect, verified over the query string and accepted through the binding path; the model's response,
     * posted to its assertion consumer service, opens its session with the attributes the model sent. Returns the
     * browser, logged in, and what the model asserted.
     *
     * @return array{Browser, Assertion, ServiceProvider}
     */
    public function loginAtTheModel(SignedParts $parts, bool $record): array
    {
        $browser = new Browser();
        $sp = $this->forModel($browser, $record);
        [$request, $relayState] = $this->authnRequestAtTheModel($browser, $sp, $record);
        $response = $this->responseTo($request, $sp);
        $assertion = $response->assertion ?? throw new LogicException('the response carries its assertion');
        $name = $parts === SignedParts::Assertion ? 'model-idp-response-signed-assertion' : 'model-idp-response-signed-both';
        $bytes = $this->write($name, new ResponseWriter()->write($response, $this->signing('idp'), $parts));
        $url = $browser->post((string) $response->destination, $this->form('SAMLResponse', $bytes, $relayState))
            ->redirect('a redirect from the assertion consumer service, the response accepted');
        if ($url !== SP . '/session.php') {
            throw new RuntimeException(sprintf('the assertion consumer service sent to %s', $url));
        }

        $session = $this->session($browser);
        $expected = [
            'authenticated' => true,
            'idp' => MODEL . '/idp',
            'nameId' => [
                'value' => $assertion->nameId->value,
                'format' => NameIdFormat::Transient->value,
                'spNameQualifier' => $sp->entityId,
            ],
            'sessionIndex' => $assertion->authnStatement->sessionIndex,
            'attributes' => self::ATTRIBUTES,
        ];
        if ($session !== $expected) {
            throw new RuntimeException(sprintf('the session of for-model holds %s', json_encode($session)));
        }
        $this->say(sprintf(
            'for-model accepted the response %s (%s) and opened its session: %s',
            $response->id,
            $name,
            json_encode($session['attributes'], JSON_UNESCAPED_SLASHES),
        ));

        return [$browser, $assertion, $sp];
    }

    /**
     * The service provider for-model logs out: its LogoutRequest, from its HTTP-Redirect, verified over the query
     * string and accepted through the binding path; the model's LogoutResponse, posted to its single logout service,
     * closes its session.
     */
    public function logoutAtTheModel(Browser $browser, Assertion $assertion, ServiceProvider $sp, bool $record): void
    {
        [$request, $relayState] = $this->logoutRequestAtTheModel($browser, $sp, $record);
        // What beffroi/saml does with it (section 6.9): the session it names is the one the model opened.
        if (
            $request->nameId->value !== $assertion->nameId->value
            || $request->sessionIndexes !== [$assertion->authnStatement->sessionIndex]
        ) {
            throw new RuntimeException('the LogoutRequest names another session than the one the model opened');
        }
        $response = $this->logoutResponseTo($request, $sp);
        $bytes = $this->write('model-idp-logoutresponse', new LogoutResponseWriter()->write($response, $this->signing('idp')));
        $url = $browser->post($response->destination, $this->form('SAMLResponse', $bytes, $relayState))
            ->redirect('a redirect from the single logout service, the LogoutResponse accepted');
        if ($url !== SP . '/session.php') {
            throw new RuntimeException(sprintf('the single logout service sent to %s', $url));
        }
        if ($this->session($browser) !== ['authenticated' => false]) {
            throw new RuntimeException('the session of for-model is still open');
        }
        $this->say(sprintf('for-model accepted the LogoutResponse %s and closed its session', $response->id));
    }

    /**
     * The model as service provider, SimpleSAMLphp's identity provider in front: the model's AuthnRequest, signed,
     * posted to its single sign-on service; the test user's login; the response it posts back, taken from its form,
     * accepted with the identity provider's metadata read live. Returns the browser, logged in at the identity
     * provider, and what the model accepted.
     *
     * @return array{Browser, AcceptedAssertion, IdentityProvider}
     */
    public function loginFromTheModel(bool $record): array
    {
        $browser = new Browser();
        $idp = $this->identityProviderLive($browser, $record);
        $request = $this->authnRequestTo($idp);
        $bytes = $this->write('model-sp-authnrequest', new AuthnRequestWriter()->write($request, $this->signing('sp')));
        $browser->post((string) $request->destination, $this->form('SAMLRequest', $bytes, 'model-login'))
            ->followWithin(IDP . '/');
        $this->say(sprintf('the identity provider took the AuthnRequest %s of the model to its login page', $request->id));
        [$xml, $relayState, $action] = $this->logIn($browser, 'SAMLResponse');
        if ($action !== MODEL . '/sp/acs' || $relayState !== 'model-login') {
            throw new RuntimeException(sprintf('the identity provider posts its response to %s', (string) $action));
        }
        if ($record) {
            $this->record('idp-response-to-model', $xml);
        }

        $accepted = new ResponseValidator(SamlLoader::create(), $this->clock, new InMemoryReplayGuard())->validate(
            UnverifiedResponse::of(SamlLoader::create()->load($xml)),
            $idp,
            ExpectedResponse::toRequest($request->id, MODEL . '/sp/acs', MODEL . '/sp'),
        );
        $this->say(sprintf(
            'the model accepted the response %s of the identity provider (%s): NameID %s, attributes %s',
            $accepted->responseId,
            $accepted->coverage->name,
            $accepted->assertion->nameId->value,
            json_encode(
                array_map(
                    static fn (Attribute $attribute): array => [$attribute->name => $attribute->values],
                    $accepted->assertion->attributes,
                ),
                JSON_UNESCAPED_SLASHES,
            ),
        ));

        return [$browser, $accepted, $idp];
    }

    /**
     * The model's service provider logs out: its LogoutRequest, signed, posted to the identity provider's single
     * logout service; the identity provider's LogoutResponse, signed since the model's entry sets sign.logout, taken
     * from its form and accepted.
     */
    public function logoutFromTheModel(Browser $browser, AcceptedAssertion $accepted, IdentityProvider $idp, bool $record): void
    {
        $request = $this->logoutRequestTo($idp, $accepted);
        $bytes = $this->write('model-sp-logoutrequest', new LogoutRequestWriter()->write($request, $this->signing('sp')));
        $browser->post($request->destination, $this->form('SAMLRequest', $bytes, 'model-logout'))->followWithin(IDP . '/');
        $xml = $this->posted($browser, 'SAMLResponse');
        $action = $browser->formAction();
        if ($action !== MODEL . '/sp/slo' || $browser->field('RelayState') !== 'model-logout') {
            throw new RuntimeException(sprintf('the identity provider posts its LogoutResponse to %s', (string) $action));
        }
        if ($record) {
            $this->record('idp-logoutresponse-to-model', $xml);
        }

        $response = new LogoutResponseValidator(SamlLoader::create(), $this->clock)->validate(
            UnverifiedLogoutResponse::of(SamlLoader::create()->load($xml)),
            $idp,
            $this->serviceProviderRole(),
            MODEL . '/sp/slo',
            $request->id,
        );
        if ($response->response->status->code !== StatusCode::Success) {
            throw new RuntimeException(sprintf('the identity provider answered %s', $response->response->status->code->name));
        }
        $this->say(sprintf(
            'the model accepted the LogoutResponse %s of the identity provider (%s), status %s',
            $response->response->id,
            $response->authentication->name,
            $response->response->status->code->name,
        ));
    }

    /**
     * Probe: a response of the model whose assertion, its only signed part, was changed after signing (an attribute
     * value), posted to for-model, which must refuse it. SimpleSAMLphp's acceptance of the model's response then
     * proves the assertion's signature, verified under the key of the model's metadata. Nothing is kept.
     */
    public function probeResponseAtTheModel(): void
    {
        $browser = new Browser();
        $sp = $this->forModel($browser, false);
        [$request, $relayState] = $this->authnRequestAtTheModel($browser, $sp, false);
        $response = $this->responseTo($request, $sp);
        $bytes = new Serializer()->serialize(new ResponseWriter()->write($response, $this->signing('idp')));
        $tampered = str_replace('model-student', 'model-teacher', $bytes);
        $this->refused(
            $browser->post((string) $response->destination, $this->form('SAMLResponse', $tampered, $relayState)),
            'a response whose assertion was changed after signing',
        );
    }

    /**
     * Probe: a LogoutResponse of the model changed after signing (its IssueInstant one second later), posted to
     * for-model, which must refuse it: validate.logout at work. Nothing is kept.
     */
    public function probeLogoutResponseAtTheModel(Browser $browser, ServiceProvider $sp): void
    {
        [$request, $relayState] = $this->logoutRequestAtTheModel($browser, $sp, false);
        $response = $this->logoutResponseTo($request, $sp);
        $bytes = new Serializer()->serialize(new LogoutResponseWriter()->write($response, $this->signing('idp')));
        $this->refused(
            $browser->post($response->destination, $this->form('SAMLResponse', $this->shifted($bytes), $relayState)),
            'a LogoutResponse changed after signing',
        );
    }

    /**
     * Probe: an AuthnRequest of the model changed after signing, posted to the identity provider, which must refuse
     * it: validate.authnrequest, which SimpleSAMLphp draws from AuthnRequestsSigned="true", at work. Nothing is kept.
     */
    public function probeAuthnRequestFromTheModel(): void
    {
        $browser = new Browser();
        $request = $this->authnRequestTo($this->identityProviderLive($browser, false));
        $bytes = new Serializer()->serialize(new AuthnRequestWriter()->write($request, $this->signing('sp')));
        $this->refused(
            $browser->post((string) $request->destination, $this->form('SAMLRequest', $this->shifted($bytes), 'model-probe')),
            'an AuthnRequest changed after signing',
        );
    }

    /**
     * Probe: a LogoutRequest of the model changed after signing, posted to the identity provider, which must refuse
     * it: validate.logout at work. The session at the identity provider stays open. Nothing is kept.
     */
    public function probeLogoutRequestFromTheModel(Browser $browser, AcceptedAssertion $accepted, IdentityProvider $idp): void
    {
        $request = $this->logoutRequestTo($idp, $accepted);
        $bytes = new Serializer()->serialize(new LogoutRequestWriter()->write($request, $this->signing('sp')));
        $this->refused(
            $browser->post($request->destination, $this->form('SAMLRequest', $this->shifted($bytes), 'model-probe')),
            'a LogoutRequest changed after signing',
        );
    }

    public function say(string $line): void
    {
        fwrite(STDOUT, $line . "\n");
    }

    /**
     * The metadata of for-model, read live, recorded when asked.
     */
    private function forModel(Browser $browser, bool $record): ServiceProvider
    {
        $metadata = $browser->get(SP . '/module.php/saml/sp/metadata/for-model');
        if ($metadata->status !== 200) {
            throw new RuntimeException(sprintf('the metadata of for-model: HTTP %d', $metadata->status));
        }
        if ($record) {
            $this->record('sp-metadata-for-model', $metadata->body);
        }

        return $this->reader()->readTrusted(SamlLoader::create()->load($metadata->body))->serviceProvider
            ?? throw new RuntimeException('the metadata of for-model holds no service provider');
    }

    /**
     * The metadata of the identity provider, read live, recorded when asked.
     */
    private function identityProviderLive(Browser $browser, bool $record): IdentityProvider
    {
        $metadata = $browser->get(IDP . '/module.php/saml/idp/metadata');
        if ($metadata->status !== 200) {
            throw new RuntimeException(sprintf('the metadata of the identity provider: HTTP %d', $metadata->status));
        }
        if ($record) {
            $this->record('idp-metadata-exchange', $metadata->body);
        }

        return $this->reader()->readTrusted(SamlLoader::create()->load($metadata->body))->identityProvider
            ?? throw new RuntimeException('the metadata of the identity provider holds no identity provider');
    }

    /**
     * for-model's login: its AuthnRequest, from its HTTP-Redirect to the model's single sign-on service, verified
     * over the query string and accepted through the binding path; recorded with its query string when asked.
     *
     * @return array{AcceptedAuthnRequest, ?string} the request and the RelayState to send back with the answer
     */
    private function authnRequestAtTheModel(Browser $browser, ServiceProvider $sp, bool $record): array
    {
        $url = $browser->get(SP . '/module.php/saml/sp/login/for-model?ReturnTo=' . urlencode(SP . '/session.php'))
            ->redirect('a redirect to the single sign-on service of the model');
        [$xml, $relayState] = $this->receiveRedirect($url, MODEL . '/idp/sso', 'SAMLRequest', $sp);
        if ($record) {
            $this->record('sp-authnrequest-to-model', $xml);
            $this->record('sp-authnrequest-to-model-query', (string) parse_url($url, PHP_URL_QUERY), 'txt');
        }
        $accepted = new AuthnRequestValidator(SamlLoader::create(), $this->clock)->validateAuthenticatedByBinding(
            UnverifiedAuthnRequest::of(SamlLoader::create()->load($xml)),
            $sp,
            $this->identityProviderRole(),
            MODEL . '/idp/sso',
        );
        $this->say(sprintf(
            'the model accepted the AuthnRequest %s of for-model (%s), its assertion consumer service %s',
            $accepted->request->id,
            $accepted->authentication->name,
            $accepted->assertionConsumerService->location,
        ));

        return [$accepted, $relayState];
    }

    /**
     * The model's answer to an accepted AuthnRequest: SimpleSAMLphp's windows (NotBefore 30 s back, 300 s ahead, a
     * session of 8 h), a transient NameID, the attributes of ATTRIBUTES.
     */
    private function responseTo(AcceptedAuthnRequest $accepted, ServiceProvider $sp): Response
    {
        $now = $this->second();
        $acs = $accepted->assertionConsumerService->location;
        $assertion = new Assertion(
            SamlId::generate(),
            $now,
            new Issuer(MODEL . '/idp'),
            new NameId(SamlId::generate(), NameIdFormat::Transient, null, $sp->entityId),
            new SubjectConfirmation($acs, $now->modify('+300 seconds'), $accepted->request->id, null),
            new Conditions($now->modify('-30 seconds'), $now->modify('+300 seconds'), [[$sp->entityId]], false),
            new AuthnStatement(
                $now,
                SamlId::generate(),
                $now->modify('+8 hours'),
                'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            ),
            array_map(
                static fn (string $name, array $values): Attribute => new Attribute($name, AttributeNameFormat::Basic, null, $values),
                array_keys(self::ATTRIBUTES),
                array_values(self::ATTRIBUTES),
            ),
        );

        return new Response(
            SamlId::generate(),
            $now,
            new Issuer(MODEL . '/idp'),
            $acs,
            $accepted->request->id,
            new Status(StatusCode::Success),
            $assertion,
        );
    }

    /**
     * for-model's logout: its LogoutRequest, from its HTTP-Redirect to the model's single logout service, verified
     * over the query string and accepted through the binding path; recorded with its query string when asked.
     *
     * @return array{LogoutRequest, ?string} the request and the RelayState to send back with the answer
     */
    private function logoutRequestAtTheModel(Browser $browser, ServiceProvider $sp, bool $record): array
    {
        $url = $browser->get(SP . '/module.php/core/logout/for-model?ReturnTo=' . urlencode(SP . '/session.php'))
            ->redirect('a redirect to the single logout service of the model');
        [$xml, $relayState] = $this->receiveRedirect($url, MODEL . '/idp/slo', 'SAMLRequest', $sp);
        if ($record) {
            $this->record('sp-logoutrequest-to-model', $xml);
            $this->record('sp-logoutrequest-to-model-query', (string) parse_url($url, PHP_URL_QUERY), 'txt');
        }
        $accepted = new LogoutRequestValidator(SamlLoader::create(), $this->clock)->validateAuthenticatedByBinding(
            UnverifiedLogoutRequest::of(SamlLoader::create()->load($xml)),
            $sp,
            $this->identityProviderRole(),
            MODEL . '/idp/slo',
        );
        $this->say(sprintf('the model accepted the LogoutRequest %s of for-model (%s)', $accepted->request->id, $accepted->authentication->name));

        return [$accepted->request, $relayState];
    }

    /**
     * The model's answer to an accepted LogoutRequest, to for-model's single logout service for HTTP-POST.
     */
    private function logoutResponseTo(LogoutRequest $request, ServiceProvider $sp): LogoutResponse
    {
        $endpoint = $this->endpoint($sp->singleLogoutServices, 'the single logout service of for-model');

        return new LogoutResponse(
            SamlId::generate(),
            $this->second(),
            new Issuer(MODEL . '/idp'),
            $endpoint->responseLocation ?? $endpoint->location,
            $request->id,
            new Status(StatusCode::Success),
        );
    }

    /**
     * The model's AuthnRequest to the identity provider's single sign-on service for HTTP-POST.
     */
    private function authnRequestTo(IdentityProvider $idp): AuthnRequest
    {
        return new AuthnRequest(
            SamlId::generate(),
            $this->second(),
            new Issuer(MODEL . '/sp'),
            $this->endpoint($idp->singleSignOnServices, 'the single sign-on service of the identity provider')->location,
            MODEL . '/sp/acs',
            null,
            Binding::HttpPost->value,
            new NameIdPolicy(NameIdFormat::Transient->value, null, true),
        );
    }

    /**
     * The model's LogoutRequest for the session an accepted response opened, to the identity provider's single logout
     * service for HTTP-POST.
     */
    private function logoutRequestTo(IdentityProvider $idp, AcceptedAssertion $accepted): LogoutRequest
    {
        $sessionIndex = $accepted->assertion->authnStatement->sessionIndex;

        return new LogoutRequest(
            SamlId::generate(),
            $this->second(),
            new Issuer(MODEL . '/sp'),
            $this->endpoint($idp->singleLogoutServices, 'the single logout service of the identity provider')->location,
            null,
            $accepted->assertion->nameId,
            $sessionIndex === null ? [] : [$sessionIndex],
        );
    }

    /**
     * The fields of the HTTP-POST binding (SAML Bindings §3.5.4): the message base64-encoded, the RelayState as it is.
     *
     * @return array<string, string>
     */
    private function form(string $field, string $bytes, ?string $relayState): array
    {
        return [$field => base64_encode($bytes)] + ($relayState === null ? [] : ['RelayState' => $relayState]);
    }

    /**
     * A probe's outcome: SimpleSAMLphp must answer with its error page, never with a redirect onwards.
     */
    private function refused(Browser $browser, string $what): void
    {
        if ($browser->status < 400) {
            throw new RuntimeException(sprintf('SimpleSAMLphp accepted %s: HTTP %d, to %s', $what, $browser->status, (string) $browser->location));
        }
        $this->say(sprintf('SimpleSAMLphp refused %s, HTTP %d%s', $what, $browser->status, $browser->error()));
    }

    /**
     * The same document, the first IssueInstant, its root's, one second later: what its signature covered changed.
     */
    private function shifted(string $bytes): string
    {
        return (string) preg_replace_callback(
            '/IssueInstant="([^"]+)"/',
            static fn (array $match): string => sprintf(
                'IssueInstant="%s"',
                new DateTimeImmutable($match[1])->modify('+1 second')->format('Y-m-d\TH:i:s\Z'),
            ),
            $bytes,
            1,
        );
    }

    /**
     * HTTP-Redirect, received, as saml2-bindings will receive it: the URL is the endpoint the message was sent to,
     * the signature over SAMLRequest or SAMLResponse, RelayState and SigAlg, in that order and as they appear in the
     * URL (SAML Bindings §3.4.4.1), verified with Verifier::verifyDetached() under the keys of the sender's metadata
     * (spec/model.md section 6.8), then the message base64-decoded and raw-inflated.
     *
     * @return array{string, ?string} the XML and the RelayState, decoded
     */
    private function receiveRedirect(string $url, string $endpoint, string $parameter, ServiceProvider|IdentityProvider $sender): array
    {
        [$location, $query] = explode('?', $url, 2) + [1 => ''];
        if ($location !== $endpoint) {
            throw new RuntimeException(sprintf('sent to %s instead of %s', $location, $endpoint));
        }
        $pairs = [];
        foreach (explode('&', $query) as $pair) {
            [$name, $value] = explode('=', $pair, 2) + [1 => ''];
            $pairs[$name] = $value;
        }
        if (! isset($pairs[$parameter], $pairs['SigAlg'], $pairs['Signature'])) {
            throw new RuntimeException('HTTP-Redirect without a signature over its query string');
        }
        $signed = $parameter . '=' . $pairs[$parameter]
            . (isset($pairs['RelayState']) ? '&RelayState=' . $pairs['RelayState'] : '')
            . '&SigAlg=' . $pairs['SigAlg'];
        new Verifier(SamlLoader::create())->verifyDetached(
            $signed,
            (string) base64_decode(urldecode($pairs['Signature']), true),
            SignatureAlgorithm::fromUri(urldecode($pairs['SigAlg'])),
            $sender->verificationKeys() ?? throw new RuntimeException('the sender publishes no signing key'),
        );
        $xml = gzinflate((string) base64_decode(urldecode($pairs[$parameter]), true));
        if (! is_string($xml) || $xml === '') {
            throw new RuntimeException('not a DEFLATE-encoded message');
        }

        return [$xml, isset($pairs['RelayState']) ? urldecode($pairs['RelayState']) : null];
    }

    /**
     * The test user's login at the identity provider, from its login form to the page whose HTTP-POST form carries
     * $field: the message decoded, the RelayState and the form's action.
     *
     * @return array{string, ?string, ?string}
     */
    private function logIn(Browser $browser, string $field): array
    {
        $authState = $browser->field('AuthState');
        if ($authState === null) {
            throw new RuntimeException(sprintf('no login form at %s (HTTP %d)%s', $browser->url, $browser->status, $browser->error()));
        }
        $action = $browser->formAction();
        $action = $action !== null && str_starts_with($action, 'http') ? $action : $browser->url;
        $browser->post($action, ['username' => self::TEST_USER, 'password' => self::TEST_PASSWORD, 'AuthState' => $authState])
            ->followWithin(IDP . '/');

        return [$this->posted($browser, $field), $browser->field('RelayState'), $browser->formAction()];
    }

    /**
     * The message an HTTP-POST form of the page carries, base64-decoded.
     */
    private function posted(Browser $browser, string $field): string
    {
        $value = $browser->field($field);
        $xml = $value === null ? false : base64_decode($value, true);
        if (! is_string($xml) || $xml === '') {
            throw new RuntimeException(sprintf('no %s form at %s (HTTP %d)%s', $field, $browser->url, $browser->status, $browser->error()));
        }

        return $xml;
    }

    /**
     * What for-model holds of its session (installation/sp/session.php).
     *
     * @return array<string, mixed>
     */
    private function session(Browser $browser): array
    {
        $session = json_decode($browser->get(SP . '/session.php')->body, true);

        return is_array($session) ? $session : throw new RuntimeException('session.php answered no JSON');
    }

    /**
     * @param list<Endpoint> $endpoints
     */
    private function endpoint(array $endpoints, string $what): Endpoint
    {
        foreach ($endpoints as $endpoint) {
            if ($endpoint->binding === Binding::HttpPost) {
                return $endpoint;
            }
        }

        throw new RuntimeException(sprintf('%s is not published for HTTP-POST', $what));
    }

    private function identityProviderRole(): IdentityProvider
    {
        return $this->identityProvider->identityProvider ?? throw new LogicException('the model is an identity provider');
    }

    private function serviceProviderRole(): ServiceProvider
    {
        return $this->serviceProvider->serviceProvider ?? throw new LogicException('the model is a service provider');
    }

    private function reader(): MetadataReader
    {
        return new MetadataReader(SamlLoader::create(), $this->clock);
    }

    /**
     * Now, to the second: the writers write times to the second, and the documents say what the objects hold.
     */
    private function second(): DateTimeImmutable
    {
        $now = $this->clock->now();

        return $now->setTime((int) $now->format('H'), (int) $now->format('i'), (int) $now->format('s'));
    }

    /**
     * @param 'idp'|'sp' $role
     */
    private function signing(string $role): Signing
    {
        return new Signing(PrivateKey::fromPem((string) file_get_contents(sprintf('%s/%s-signing-key.pem', $this->keys, $role))));
    }

    /**
     * @param 'idp'|'sp' $role
     */
    private function certificate(string $role): string
    {
        $pem = (string) file_get_contents(sprintf('%s/%s-signing-certificate.pem', $this->keys, $role));

        return (string) preg_replace('~-----[A-Z ]+-----|\s+~', '', $pem);
    }

    /**
     * A document the model wrote, serialized by Core, into written/.
     */
    private function write(string $name, Document $document): string
    {
        $bytes = new Serializer()->serialize($document);
        file_put_contents(sprintf('%s/%s.xml', $this->written, $name), $bytes);

        return $bytes;
    }

    /**
     * A document SimpleSAMLphp sent, bytes as decoded, named as phase 1 names its captures.
     */
    private function record(string $what, string $bytes, string $extension = 'xml'): void
    {
        $file = sprintf('%s/simplesamlphp-%s-%s-%s.%s', $this->received, VERSION, $what, $this->today, $extension);
        file_put_contents($file, $bytes);
        $this->say(sprintf('recorded %s (%d bytes)', basename($file), strlen($bytes)));
    }
}

$keep = in_array('--keep', $argv, true);
$received = $keep ? __DIR__ . '/../../Fixture/real' : __DIR__ . '/received';
foreach ([__DIR__ . '/written', $received] as $directory) {
    if (! is_dir($directory)) {
        mkdir($directory);
    }
}
foreach (glob(__DIR__ . '/written/*.xml') ?: [] as $file) {
    unlink($file);
}
$exchange = new Exchange(__DIR__ . '/written', $received, __DIR__ . '/../../Fixture/keys');
$exchange->writeMetadata();

$failures = [];
$step = static function (string $name, Closure $run) use ($exchange, &$failures): mixed {
    $exchange->say('== ' . $name);
    try {
        return $run();
    } catch (Throwable $failure) {
        $failures[] = $name;
        $exchange->say(sprintf('FAIL %s: %s: %s', $name, $failure::class, $failure->getMessage()));

        return null;
    }
};

$login = $step(
    'the model as identity provider, the response with its signed assertion',
    static fn (): array => $exchange->loginAtTheModel(SignedParts::Assertion, false),
);
if (is_array($login)) {
    $step(
        'probe: for-model and a LogoutResponse of the model changed after signing',
        static fn () => $exchange->probeLogoutResponseAtTheModel($login[0], $login[2]),
    );
}
$login = $step(
    'the model as identity provider, the response signed over its signed assertion',
    static fn (): array => $exchange->loginAtTheModel(SignedParts::AssertionAndResponse, true),
);
if (is_array($login)) {
    $step(
        'logout, from SimpleSAMLphp\'s service provider to the model',
        static fn () => $exchange->logoutAtTheModel($login[0], $login[1], $login[2], true),
    );
}
$step(
    'probe: for-model and a response of the model changed after signing',
    static fn () => $exchange->probeResponseAtTheModel(),
);
$login = $step('the model as service provider', static fn (): array => $exchange->loginFromTheModel(true));
if (is_array($login)) {
    $step(
        'probe: the identity provider and a LogoutRequest of the model changed after signing',
        static fn () => $exchange->probeLogoutRequestFromTheModel($login[0], $login[1], $login[2]),
    );
    $step(
        'logout, from the model to SimpleSAMLphp\'s identity provider',
        static fn () => $exchange->logoutFromTheModel($login[0], $login[1], $login[2], true),
    );
}
$step(
    'probe: the identity provider and an AuthnRequest of the model changed after signing',
    static fn () => $exchange->probeAuthnRequestFromTheModel(),
);

$exchange->say($failures === [] ? 'every step green' : sprintf('%d step(s) failed: %s', count($failures), implode('; ', $failures)));
exit($failures === [] ? 0 : 1);
