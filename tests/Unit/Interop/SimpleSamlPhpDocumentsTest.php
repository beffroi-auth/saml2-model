<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Interop;

use Beffroi\Saml2\Model\Assertion\Attribute;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Protocol\UnverifiedAuthnRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutResponse;
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\LogoutRequestValidator;
use Beffroi\Saml2\Model\Validation\LogoutResponseValidator;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\Verifier;
use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function array_map;
use function base64_decode;
use function explode;
use function gzinflate;
use function urldecode;

/**
 * Section 9.4, section 9.5: what SimpleSAMLphp 2.5.3.1 sent the model in the exchange of story #11 on 30 September
 * 2026 (tests/Interop/simplesamlphp/README.md, section 4), bytes as received, validated with a clock frozen at their
 * IssueInstant: its identity provider's response and LogoutResponse to the model's service provider, its service
 * provider for-model's AuthnRequest and LogoutRequest to the model's identity provider, with the query strings
 * HTTP-Redirect carried them in, and the metadata of both parties as they were served. The model's two roles are
 * those the exchange wrote into its metadata (tests/Interop/simplesamlphp/exchange.php).
 */
final class SimpleSamlPhpDocumentsTest extends TestCase
{
    private const string IDP_METADATA = 'simplesamlphp-2.5.3.1-idp-metadata-exchange-2026-09-30.xml';

    private const string SP_METADATA = 'simplesamlphp-2.5.3.1-sp-metadata-for-model-2026-09-30.xml';

    private const string IDP = 'http://localhost:8081/simplesaml/module.php/saml/idp/';

    private const string SP = 'http://localhost:8082/simplesaml/module.php/saml/sp/';

    private const string MODEL = 'http://localhost:8083/model/';

    /**
     * Section 9.5, section 6.1, M-2: the response of SimpleSAMLphp's identity provider to the model's AuthnRequest
     * (_627d4a4e...), its response and its assertion signed, as by default, accepted under the identity provider's
     * metadata with the attributes of the test user.
     */
    #[Test]
    public function itAcceptsTheResponseToTheModel(): void
    {
        // Given
        $response = UnverifiedResponse::of(MetadataFixtures::load('real/simplesamlphp-2.5.3.1-idp-response-to-model-2026-09-30.xml'));
        $validator = new ResponseValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-09-30T13:07:34Z')),
            new InMemoryReplayGuard(),
        );

        // When
        $accepted = $validator->validate(
            $response,
            $this->identityProvider(),
            ExpectedResponse::toRequest(
                '_627d4a4e07a25eca1ecd548b41255f1003276fe8',
                self::MODEL . 'sp/acs',
                self::MODEL . 'sp',
            ),
        );

        // Then
        static::assertSame(
            [
                SignatureCoverage::AssertionAndResponse,
                self::IDP . 'metadata',
                NameIdFormat::Transient,
                self::MODEL . 'sp',
                [['uid', ['test']], ['eduPersonAffiliation', ['member', 'student']]],
            ],
            [
                $accepted->coverage,
                $accepted->assertion->issuer->entityId,
                $accepted->assertion->nameId->format,
                $accepted->assertion->nameId->spNameQualifier,
                array_map(
                    static fn (Attribute $attribute): array => [$attribute->name, $attribute->values],
                    $accepted->assertion->attributes,
                ),
            ],
        );
    }

    /**
     * Section 9.5, section 6.4, M-2, M-10: the LogoutResponse of SimpleSAMLphp's identity provider to the model's
     * LogoutRequest (_4155d5bb...), signed in the XML since its entry for the model sets sign.logout (finding F-1),
     * posted over HTTP-POST, accepted by validate().
     */
    #[Test]
    public function itAcceptsTheSignedLogoutResponseToTheModel(): void
    {
        // Given
        $response = UnverifiedLogoutResponse::of(
            MetadataFixtures::load('real/simplesamlphp-2.5.3.1-idp-logoutresponse-to-model-2026-09-30.xml'),
        );
        $validator = new LogoutResponseValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-09-30T13:07:35Z')),
        );

        // When
        $accepted = $validator->validate(
            $response,
            $this->identityProvider(),
            $this->modelServiceProvider(),
            self::MODEL . 'sp/slo',
            '_4155d5bbb2fdcf7e726ce667ddfefea37eada958',
        );

        // Then
        static::assertSame(
            [Authentication::XmlSignature, '_8496a6eb1c647966d9b188d1f03d6fd2bffec1cc07', StatusCode::Success],
            [$accepted->authentication, $accepted->response->id, $accepted->response->status->code],
        );
    }

    /**
     * Section 6.8, Bindings §3.4.4.1: the signature over the query string that carried each request of for-model to
     * the model, the octets of SAMLRequest, RelayState and SigAlg as they appear in the URL, verified under the key of
     * for-model's metadata, what saml2-bindings does before it calls validateAuthenticatedByBinding().
     */
    #[Test]
    #[DataProvider('provideQueryStrings')]
    public function itVerifiesTheQueryStringOfARequestToTheModel(string $query): void
    {
        // Given
        $parameters = $this->parameters($query);
        $keys = $this->serviceProvider()->verificationKeys() ?? static::fail('for-model publishes a signing key.');

        // When
        $key = new Verifier(SamlLoader::create())->verifyDetached(
            'SAMLRequest='
            . $parameters['SAMLRequest']
            . '&RelayState='
            . $parameters['RelayState']
            . '&SigAlg='
            . $parameters['SigAlg'],
            (string) base64_decode(urldecode($parameters['Signature']), true),
            SignatureAlgorithm::fromUri(urldecode($parameters['SigAlg'])),
            $keys,
        );

        // Then
        static::assertSame($keys->keys[0], $key);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideQueryStrings(): iterable
    {
        yield 'the AuthnRequest' => ['simplesamlphp-2.5.3.1-sp-authnrequest-to-model-query-2026-09-30.txt'];
        yield 'the LogoutRequest' => ['simplesamlphp-2.5.3.1-sp-logoutrequest-to-model-query-2026-09-30.txt'];
    }

    /**
     * Section 9.4: the XML of each request of for-model to the model is what its query string carried, base64-decoded
     * and raw-inflated, byte for byte.
     */
    #[Test]
    #[DataProvider('provideRedirected')]
    public function itCarriesInItsQueryStringTheRequestKept(string $query, string $xml): void
    {
        // Given
        $parameters = $this->parameters($query);

        // When
        $inflated = gzinflate((string) base64_decode(urldecode($parameters['SAMLRequest']), true));

        // Then
        static::assertSame(MetadataFixtures::bytes('real/' . $xml), $inflated);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideRedirected(): iterable
    {
        yield 'the AuthnRequest' => [
            'simplesamlphp-2.5.3.1-sp-authnrequest-to-model-query-2026-09-30.txt',
            'simplesamlphp-2.5.3.1-sp-authnrequest-to-model-2026-09-30.xml',
        ];
        yield 'the LogoutRequest' => [
            'simplesamlphp-2.5.3.1-sp-logoutrequest-to-model-query-2026-09-30.txt',
            'simplesamlphp-2.5.3.1-sp-logoutrequest-to-model-2026-09-30.xml',
        ];
    }

    /**
     * Section 9.5, section 6.2, M-9: the AuthnRequest of for-model to the model's identity provider, authenticated
     * by its query string, accepted through the binding path, its assertion consumer service the HTTP-POST one of
     * for-model's metadata.
     */
    #[Test]
    public function itAcceptsTheAuthnRequestToTheModelThroughTheBinding(): void
    {
        // Given
        $request = UnverifiedAuthnRequest::of(
            MetadataFixtures::load('real/simplesamlphp-2.5.3.1-sp-authnrequest-to-model-2026-09-30.xml'),
        );
        $validator = new AuthnRequestValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-09-30T13:07:34Z')),
        );

        // When
        $accepted = $validator->validateAuthenticatedByBinding(
            $request,
            $this->serviceProvider(),
            $this->modelIdentityProvider(),
            self::MODEL . 'idp/sso',
        );

        // Then
        static::assertSame(
            [
                Authentication::Binding,
                '_ef4cb04a9098a02745f19851d7b70d2e7712c1aa4d',
                self::SP . 'metadata/for-model',
                self::SP . 'saml2-acs.php/for-model',
            ],
            [
                $accepted->authentication,
                $accepted->request->id,
                $accepted->request->issuer->entityId,
                $accepted->assertionConsumerService->location,
            ],
        );
    }

    /**
     * Section 9.5, section 6.3: the LogoutRequest of for-model to the model's identity provider, authenticated by its
     * query string, accepted through the binding path, naming the transient NameID and the session the model issued.
     */
    #[Test]
    public function itAcceptsTheLogoutRequestToTheModelThroughTheBinding(): void
    {
        // Given
        $request = UnverifiedLogoutRequest::of(
            MetadataFixtures::load('real/simplesamlphp-2.5.3.1-sp-logoutrequest-to-model-2026-09-30.xml'),
        );
        $validator = new LogoutRequestValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-09-30T13:07:34Z')),
        );

        // When
        $accepted = $validator->validateAuthenticatedByBinding(
            $request,
            $this->serviceProvider(),
            $this->modelIdentityProvider(),
            self::MODEL . 'idp/slo',
        );

        // Then
        static::assertSame(
            [
                Authentication::Binding,
                '_b00d8f15bcc6e09626c3d388ce705bb778563bbf5e',
                NameIdFormat::Transient,
                '_a849fe5baadb7fb8e8c621c19269ce4f976adf46',
                ['_0b87387ced75ba1b87f2080d912ff64d06a11e49'],
            ],
            [
                $accepted->authentication,
                $accepted->request->id,
                $accepted->request->nameId->format,
                $accepted->request->nameId->value,
                $accepted->request->sessionIndexes,
            ],
        );
    }

    /**
     * Section 6.5: the identity provider's metadata in the configuration of the exchange, where it publishes its
     * single sign-on and single logout services for HTTP-POST next to HTTP-Redirect, at the same locations.
     */
    #[Test]
    public function itReadsTheBindingsTheIdentityProviderPublishesForTheExchange(): void
    {
        // When
        $idp = $this->identityProvider();

        // Then
        static::assertEquals(
            [
                [
                    new Endpoint(Binding::HttpRedirect, self::IDP . 'singleSignOnService'),
                    new Endpoint(Binding::HttpPost, self::IDP . 'singleSignOnService'),
                ],
                [
                    new Endpoint(Binding::HttpRedirect, self::IDP . 'singleLogout'),
                    new Endpoint(Binding::HttpPost, self::IDP . 'singleLogout'),
                ],
            ],
            [$idp->singleSignOnServices, $idp->singleLogoutServices],
        );
    }

    /**
     * Section 6.5: for-model's metadata, its HTTP-Artifact assertion consumer service dropped, its single logout
     * service published for HTTP-POST next to HTTP-Redirect, where the model answers.
     */
    #[Test]
    public function itReadsTheEndpointsOfTheServiceProviderForTheModel(): void
    {
        // When
        $sp = $this->serviceProvider();

        // Then
        static::assertEquals(
            [
                [new IndexedEndpoint(Binding::HttpPost, self::SP . 'saml2-acs.php/for-model', 0)],
                [
                    new Endpoint(Binding::HttpRedirect, self::SP . 'saml2-logout.php/for-model'),
                    new Endpoint(Binding::HttpPost, self::SP . 'saml2-logout.php/for-model'),
                ],
                true,
            ],
            [$sp->assertionConsumerServices->endpoints, $sp->singleLogoutServices, $sp->authnRequestsSigned],
        );
    }

    /**
     * The parameters of a query string of tests/Fixture/real/, as they appear in the URL, not decoded.
     *
     * @return array<string, string>
     */
    private function parameters(string $file): array
    {
        $parameters = [];
        foreach (explode('&', MetadataFixtures::bytes('real/' . $file)) as $pair) {
            [$name, $value] = explode('=', $pair, 2) + [1 => ''];
            $parameters[$name] = $value;
        }

        return $parameters;
    }

    private function identityProvider(): IdentityProvider
    {
        return (
            $this->descriptor(self::IDP_METADATA)->identityProvider ?? throw new LogicException('The metadata holds an identity provider.')
        );
    }

    private function serviceProvider(): ServiceProvider
    {
        return (
            $this->descriptor(self::SP_METADATA)->serviceProvider ?? throw new LogicException('The metadata holds a service provider.')
        );
    }

    /**
     * A metadata of the exchange read by readTrusted() with a clock at its capture.
     */
    private function descriptor(string $file): EntityDescriptor
    {
        return new MetadataReader(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-09-30T13:07:34Z')),
        )->readTrusted(MetadataFixtures::load('real/' . $file));
    }

    /**
     * The model's identity provider as the exchange published it: the test key, HTTP-Redirect for its single
     * sign-on and single logout services, where for-model sent its requests.
     */
    private function modelIdentityProvider(): IdentityProvider
    {
        return new IdentityProvider(
            self::MODEL . 'idp',
            [MetadataFixtures::certificate('idp')],
            [],
            [new Endpoint(Binding::HttpRedirect, self::MODEL . 'idp/sso')],
            [new Endpoint(Binding::HttpRedirect, self::MODEL . 'idp/slo')],
            [NameIdFormat::Transient],
            true,
        );
    }

    /**
     * The model's service provider as the exchange published it: the test key, HTTP-POST for its assertion consumer
     * service and its single logout service.
     */
    private function modelServiceProvider(): ServiceProvider
    {
        return new ServiceProvider(
            self::MODEL . 'sp',
            [MetadataFixtures::certificate('sp')],
            [],
            new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, self::MODEL . 'sp/acs', 0, true)]),
            [new Endpoint(Binding::HttpPost, self::MODEL . 'sp/slo')],
            [NameIdFormat::Transient],
            true,
            true,
        );
    }
}
