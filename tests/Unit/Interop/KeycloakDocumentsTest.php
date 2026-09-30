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
use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 9.4, section 9.5: what Keycloak 26.7.4 wrote in the exchange with the model of 30 September 2026
 * (tests/Interop/keycloak/README.md), bytes as received, each validated with a clock frozen at its IssueInstant: the
 * broker of realm sp configured from the model's identity provider metadata, which signs its requests and posts them,
 * and realm idp answering the model's service provider. The model's own roles are the ones its metadata described in
 * that run, with the test keys of tests/Fixture/keys/; the IDs of the model's requests are those the run printed.
 */
final class KeycloakDocumentsTest extends TestCase
{
    private const string BROKER = 'http://localhost:8180/realms/sp';

    private const string BROKER_ENDPOINT = 'http://localhost:8180/realms/sp/broker/model/endpoint';

    private const string REALM_IDP = 'http://localhost:8180/realms/idp';

    private const string MODEL_IDP = 'https://idp.saml2-model.test/metadata';

    private const string MODEL_SSO = 'https://idp.saml2-model.test/sso';

    private const string MODEL_IDP_SLO = 'https://idp.saml2-model.test/slo';

    private const string MODEL_SP = 'https://sp.saml2-model.test/metadata';

    private const string MODEL_ACS = 'https://sp.saml2-model.test/acs';

    private const string MODEL_SP_SLO = 'https://sp.saml2-model.test/slo';

    /**
     * Section 6.5, M-3: the metadata of the broker configured from the model's (WantAuthnRequestsSigned="true"),
     * which publishes the signing key its unsigned default left out, and makes its HTTP-POST consumer service the
     * default one.
     */
    #[Test]
    public function itReadsTheMetadataOfTheBrokerThatSigns(): void
    {
        // Given
        $document = MetadataFixtures::load('real/keycloak-26.7.4-exchange-broker-metadata-2026-09-30.xml');

        // When
        $broker =
            $this->reader()->readTrusted($document)->serviceProvider ?? throw new LogicException('The metadata holds a service provider.');

        // Then
        static::assertSame(
            [
                self::BROKER,
                1,
                true,
                true,
                [Binding::HttpPost, self::BROKER_ENDPOINT, 1],
                [[Binding::HttpPost, self::BROKER_ENDPOINT], [Binding::HttpRedirect, self::BROKER_ENDPOINT]],
            ],
            [
                $broker->entityId,
                count($broker->signingCertificates),
                $broker->authnRequestsSigned,
                $broker->wantAssertionsSigned,
                [
                    $broker->assertionConsumerServices->default()->binding,
                    $broker->assertionConsumerServices->default()->location,
                    $broker->assertionConsumerServices->default()->index,
                ],
                array_map(
                    static fn (Endpoint $endpoint): array => [$endpoint->binding, $endpoint->location],
                    $broker->singleLogoutServices,
                ),
            ],
        );
    }

    /**
     * Section 6.2, M-2, M-9, finding F1 of tests/Interop/keycloak/README.md: the AuthnRequest the broker posted to the
     * model's single sign-on service, signed in XML, asking for its response over HTTP-POST, accepted by validate().
     */
    #[Test]
    public function itAcceptsTheSignedRequestOfTheBroker(): void
    {
        // Given
        $request = UnverifiedAuthnRequest::of(
            MetadataFixtures::load('real/keycloak-26.7.4-exchange-broker-authn-request-2026-09-30.xml'),
        );

        // When
        $accepted = new AuthnRequestValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-09-30T13:02:34.065Z')),
        )->validate($request, $this->broker(), $this->modelIdentityProvider(), self::MODEL_SSO);

        // Then
        static::assertSame(
            [
                Authentication::XmlSignature,
                'ID_fdae0d1a-7165-4939-be02-2cc70ac0b155',
                self::BROKER,
                'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
                true,
                self::BROKER_ENDPOINT,
                1,
            ],
            [
                $accepted->authentication,
                $accepted->request->id,
                $accepted->request->issuer->entityId,
                $accepted->request->protocolBinding,
                $accepted->request->nameIdPolicy?->format,
                $accepted->request->nameIdPolicy?->allowCreate,
                $accepted->assertionConsumerService->location,
                $accepted->assertionConsumerService->index,
            ],
        );
    }

    /**
     * Section 6.3, M-2, finding F2 of tests/Interop/keycloak/README.md: the LogoutRequest the broker posted to the
     * model's single logout service, signed in XML, naming the subject and the session of the model's assertion,
     * accepted by validate().
     */
    #[Test]
    public function itAcceptsTheSignedLogoutRequestOfTheBroker(): void
    {
        // Given
        $request = UnverifiedLogoutRequest::of(
            MetadataFixtures::load('real/keycloak-26.7.4-exchange-broker-logout-request-2026-09-30.xml'),
        );

        // When
        $accepted = new LogoutRequestValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-09-30T13:02:34.236Z')),
        )->validate($request, $this->broker(), $this->modelIdentityProvider(), self::MODEL_IDP_SLO);

        // Then
        static::assertSame(
            [
                Authentication::XmlSignature,
                'ID_7fb80c65-0821-4bee-a28d-1bd88def3f61',
                'model-alice',
                NameIdFormat::Persistent,
                ['_2a9f36d46739894e683decb7f7705c0dcf19635a'],
                null,
            ],
            [
                $accepted->authentication,
                $accepted->request->id,
                $accepted->request->nameId->value,
                $accepted->request->nameId->format,
                $accepted->request->sessionIndexes,
                $accepted->request->notOnOrAfter,
            ],
        );
    }

    /**
     * Section 6.1, M-2: the response realm idp posted to the model's assertion consumer service, answering the model's
     * signed AuthnRequest, the response signed and not the assertion, with Keycloak's six attributes named Role.
     */
    #[Test]
    public function itAcceptsTheResponseOfRealmIdpToTheModel(): void
    {
        // Given
        $response = UnverifiedResponse::of(
            MetadataFixtures::load('real/keycloak-26.7.4-exchange-idp-response-2026-09-30.xml'),
        );

        // When
        $accepted = new ResponseValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-09-30T13:02:34.391Z')),
            new InMemoryReplayGuard(),
        )->validate(
            $response,
            $this->realmIdp(),
            ExpectedResponse::toRequest('_8b44214fbfab0a7dccde575a0028ce774831e27f', self::MODEL_ACS, self::MODEL_SP),
        );

        // Then
        static::assertSame(
            [
                SignatureCoverage::Response,
                'ID_19abf153-cab9-41ae-9f81-76b13888fe0a',
                'G-41eee78d-0ec1-43d9-b7fc-584c8bccc500',
                NameIdFormat::Persistent,
                '_95NiAiPWiL8nAJmSq5Hlflp::e23c7b4f-7c1b-45c3-8ded-744f3c749829',
                ['Role', 'Role', 'Role', 'Role', 'Role', 'Role'],
            ],
            [
                $accepted->coverage,
                $accepted->responseId,
                $accepted->assertion->nameId->value,
                $accepted->assertion->nameId->format,
                $accepted->assertion->authnStatement->sessionIndex,
                array_map(
                    static fn (Attribute $attribute): string => $attribute->name,
                    $accepted->assertion->attributes,
                ),
            ],
        );
    }

    /**
     * Section 6.4, M-2, M-10: the LogoutResponse realm idp posted to the model's single logout service, signed,
     * answering the model's signed LogoutRequest, accepted by validate().
     */
    #[Test]
    public function itAcceptsTheLogoutResponseOfRealmIdpToTheModel(): void
    {
        // Given
        $response = UnverifiedLogoutResponse::of(
            MetadataFixtures::load('real/keycloak-26.7.4-exchange-idp-logout-response-2026-09-30.xml'),
        );

        // When
        $accepted = new LogoutResponseValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-09-30T13:02:34.450Z')),
        )->validate(
            $response,
            $this->realmIdp(),
            $this->modelServiceProvider(),
            self::MODEL_SP_SLO,
            '_9f51ef48331c006c5d1afd246989666af224d283',
        );

        // Then
        static::assertSame(
            [
                Authentication::XmlSignature,
                'ID_0f8c9087-49ff-4053-bd42-a0faed07f994',
                self::REALM_IDP,
                StatusCode::Success,
            ],
            [
                $accepted->authentication,
                $accepted->response->id,
                $accepted->response->issuer->entityId,
                $accepted->response->status->code,
            ],
        );
    }

    /**
     * The model's identity provider as its metadata described it in the exchange: signed requests wanted, HTTP-POST
     * services only.
     */
    private function modelIdentityProvider(): IdentityProvider
    {
        return new IdentityProvider(
            self::MODEL_IDP,
            [MetadataFixtures::certificate('idp')],
            [],
            [new Endpoint(Binding::HttpPost, self::MODEL_SSO)],
            [new Endpoint(Binding::HttpPost, self::MODEL_IDP_SLO)],
            [NameIdFormat::Persistent],
            true,
        );
    }

    /**
     * The model's service provider as its metadata described it in the exchange.
     */
    private function modelServiceProvider(): ServiceProvider
    {
        return new ServiceProvider(
            self::MODEL_SP,
            [MetadataFixtures::certificate('sp')],
            [],
            new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, self::MODEL_ACS, 0, true)]),
            [new Endpoint(Binding::HttpPost, self::MODEL_SP_SLO)],
            [],
            true,
            false,
        );
    }

    private function broker(): ServiceProvider
    {
        return (
            $this->metadata('keycloak-26.7.4-exchange-broker-metadata-2026-09-30.xml')->serviceProvider ?? throw new LogicException('The metadata holds a service provider.')
        );
    }

    private function realmIdp(): IdentityProvider
    {
        return (
            $this->metadata('keycloak-26.7.4-exchange-idp-metadata-2026-09-30.xml')->identityProvider ?? throw new LogicException('The metadata holds an identity provider.')
        );
    }

    /**
     * A metadata of the same run, read by readTrusted() at the time of the run.
     */
    private function metadata(string $file): EntityDescriptor
    {
        return $this->reader()->readTrusted(MetadataFixtures::load('real/' . $file));
    }

    private function reader(): MetadataReader
    {
        return new MetadataReader(SamlLoader::create(), new FrozenClock(new DateTimeImmutable('2026-09-30T13:02:34Z')));
    }
}
