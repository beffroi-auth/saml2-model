<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Validation;

use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutResponse;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Validation\LogoutRequestValidator;
use Beffroi\Saml2\Model\Validation\LogoutResponseValidator;
use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 9.4: the logout messages of tests/Fixture/real/, bytes as received, validated with a clock frozen at their
 * IssueInstant, each between the two parties of the metadata captured with it. The signed ones are accepted by
 * validate(); SimpleSAMLphp's request, which HTTP-Redirect carried with a signature over the query string that the
 * capture verified and did not keep, by validateAuthenticatedByBinding(); the two that no signature authenticated,
 * neither in the XML nor in the query string, are refused by validate(), as section 6.8 has the binding do.
 */
final class LogoutRealDocumentsTest extends TestCase
{
    private const string SIMPLESAMLPHP_IDP = 'simplesamlphp-2.5.3.1-idp-metadata-2026-09-30.xml';

    private const string SIMPLESAMLPHP_SP = 'simplesamlphp-2.5.3.1-sp-metadata-2026-09-30.xml';

    private const string LIBRARY_IDP = 'simplesamlphp-saml2-4.20.3-idp-metadata-2026-09-30.xml';

    private const string LIBRARY_SP = 'simplesamlphp-saml2-4.20.3-sp-metadata-2026-09-30.xml';

    private const string KEYCLOAK_IDP = 'keycloak-26.7.4-idp-metadata-2026-09-30.xml';

    private const string KEYCLOAK_SP = 'keycloak-26.7.4-sp-metadata-2026-09-30.xml';

    /**
     * Section 9.4, section 6.8: the LogoutRequest of SimpleSAMLphp 2.5.3.1's service provider, which arrived at the
     * identity provider over HTTP-Redirect with a signature over the query string, accepted through the binding path.
     */
    #[Test]
    public function itAcceptsTheRequestOfSimpleSamlPhpThroughTheBinding(): void
    {
        // Given
        $request = UnverifiedLogoutRequest::of(
            MetadataFixtures::load('real/simplesamlphp-2.5.3.1-sp-logoutrequest-2026-09-30.xml'),
        );

        // When
        $accepted = $this->requestValidator('2026-09-30T10:34:38Z')->validateAuthenticatedByBinding(
            $request,
            $this->serviceProvider(self::SIMPLESAMLPHP_SP),
            $this->identityProvider(self::SIMPLESAMLPHP_IDP),
            'http://localhost:8081/simplesaml/module.php/saml/idp/singleLogout',
        );

        // Then
        static::assertSame(
            [
                Authentication::Binding,
                'http://localhost:8082/simplesaml/module.php/saml/sp/metadata/default-sp',
                NameIdFormat::Transient,
                '_29c3aafd4bdf96819de7bceca1d2e0e40ec80c48f1',
                ['_ac4fefa416ace865398d3efa1b7ba04405f388bdd0'],
            ],
            [
                $accepted->authentication,
                $accepted->request->issuer->entityId,
                $accepted->request->nameId->format,
                $accepted->request->nameId->value,
                $accepted->request->sessionIndexes,
            ],
        );
    }

    /**
     * Section 9.4, M-2, SAML Profiles §4.4.4.2: the LogoutResponse of SimpleSAMLphp 2.5.3.1's identity provider, which
     * no signature covers, in the XML or over the query string (finding F-1 of story #11), refused by validate().
     */
    #[Test]
    public function itRefusesTheUnsignedResponseOfSimpleSamlPhp(): void
    {
        // Given
        $response = UnverifiedLogoutResponse::of(
            MetadataFixtures::load('real/simplesamlphp-2.5.3.1-idp-logoutresponse-2026-09-30.xml'),
        );

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The message carries no ds:Signature, which the profile requires (M-2).');

        // When
        $this->responseValidator('2026-09-30T10:34:39Z')->validate(
            $response,
            $this->identityProvider(self::SIMPLESAMLPHP_IDP),
            $this->serviceProvider(self::SIMPLESAMLPHP_SP),
            'http://localhost:8082/simplesaml/module.php/saml/sp/saml2-logout.php/default-sp',
            '_10771973ed20759cbd9e0a77611d8d04c60ed3fa49',
        );
    }

    /**
     * Section 9.4, M-2, M-3: the LogoutRequest simplesamlphp/saml2 4.20.3 signed with the service provider's test key,
     * verified under the certificate of the service provider's metadata, not the one of its own KeyInfo.
     */
    #[Test]
    public function itAcceptsTheSignedRequestOfTheLibrary(): void
    {
        // Given
        $request = UnverifiedLogoutRequest::of(
            MetadataFixtures::load('real/simplesamlphp-saml2-4.20.3-logoutrequest-signed-2026-09-30.xml'),
        );

        // When
        $accepted = $this->requestValidator('2026-09-30T12:01:00Z')->validate(
            $request,
            $this->serviceProvider(self::LIBRARY_SP),
            $this->identityProvider(self::LIBRARY_IDP),
            'https://idp.example.org/slo',
        );

        // Then
        static::assertSame(
            [
                Authentication::XmlSignature,
                '_ssp-lib-logoutrequest-0001',
                'https://sp.example.org',
                '_ssp-lib-transient-0001',
                ['_ssp-lib-session-0001'],
            ],
            [
                $accepted->authentication,
                $accepted->request->id,
                $accepted->request->issuer->entityId,
                $accepted->request->nameId->value,
                $accepted->request->sessionIndexes,
            ],
        );
    }

    /**
     * Section 9.4, M-2, M-10: the LogoutResponse simplesamlphp/saml2 4.20.3 signed with the identity provider's test
     * key, answering the library's request.
     */
    #[Test]
    public function itAcceptsTheSignedResponseOfTheLibrary(): void
    {
        // Given
        $response = UnverifiedLogoutResponse::of(
            MetadataFixtures::load('real/simplesamlphp-saml2-4.20.3-logoutresponse-signed-2026-09-30.xml'),
        );

        // When
        $accepted = $this->responseValidator('2026-09-30T12:01:01Z')->validate(
            $response,
            $this->identityProvider(self::LIBRARY_IDP),
            $this->serviceProvider(self::LIBRARY_SP),
            'https://sp.example.org/slo',
            '_ssp-lib-logoutrequest-0001',
        );

        // Then
        static::assertSame(
            [Authentication::XmlSignature, '_ssp-lib-logoutresponse-0001', StatusCode::Success, null],
            [
                $accepted->authentication,
                $accepted->response->id,
                $accepted->response->status->code,
                $accepted->response->status->secondLevel,
            ],
        );
    }

    /**
     * Section 9.4, M-2, M-3: the LogoutRequest of Keycloak 26.7.4's broker, sent over HTTP-Redirect without any
     * signature, refused by validate(): the broker's metadata publishes no signing key either.
     */
    #[Test]
    public function itRefusesTheUnsignedRequestOfKeycloak(): void
    {
        // Given
        $request = UnverifiedLogoutRequest::of(
            MetadataFixtures::load('real/keycloak-26.7.4-sp-logout-request-2026-09-30.xml'),
        );

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The metadata of the peer holds no signing key to verify the message with (M-3).');

        // When
        $this->requestValidator('2026-09-30T10:27:56.721Z')->validate(
            $request,
            $this->serviceProvider(self::KEYCLOAK_SP),
            $this->identityProvider(self::KEYCLOAK_IDP),
            'http://localhost:8180/realms/idp/protocol/saml',
        );
    }

    /**
     * Section 9.4, M-2, M-10: the signed LogoutResponse of Keycloak 26.7.4's identity provider, posted to its broker,
     * its Issuer in the default namespace, its signature with the dsig prefix, its IssueInstant in milliseconds.
     */
    #[Test]
    public function itAcceptsTheSignedResponseOfKeycloak(): void
    {
        // Given
        $response = UnverifiedLogoutResponse::of(
            MetadataFixtures::load('real/keycloak-26.7.4-idp-logout-response-2026-09-30.xml'),
        );

        // When
        $accepted = $this->responseValidator('2026-09-30T10:27:56.779Z')->validate(
            $response,
            $this->identityProvider(self::KEYCLOAK_IDP),
            $this->serviceProvider(self::KEYCLOAK_SP),
            'http://localhost:8180/realms/sp/broker/idp/endpoint',
            'ID_19a3a74f-b524-4a06-8611-a85b36cbb4fa',
        );

        // Then
        static::assertSame(
            [
                Authentication::XmlSignature,
                'ID_841b9168-36d0-4aea-8454-df8f5d8383ef',
                'http://localhost:8180/realms/idp',
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

    private function identityProvider(string $file): IdentityProvider
    {
        return (
            $this->descriptor($file)->identityProvider ?? throw new LogicException('The metadata holds an identity provider.')
        );
    }

    private function serviceProvider(string $file): ServiceProvider
    {
        return (
            $this->descriptor($file)->serviceProvider ?? throw new LogicException('The metadata holds a service provider.')
        );
    }

    /**
     * A real metadata read by readTrusted() with a clock at its capture.
     */
    private function descriptor(string $file): EntityDescriptor
    {
        return new MetadataReader(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-09-30T12:00:00Z')),
        )->readTrusted(MetadataFixtures::load('real/' . $file));
    }

    private function requestValidator(string $now): LogoutRequestValidator
    {
        return new LogoutRequestValidator(SamlLoader::create(), new FrozenClock(new DateTimeImmutable($now)));
    }

    private function responseValidator(string $now): LogoutResponseValidator
    {
        return new LogoutResponseValidator(SamlLoader::create(), new FrozenClock(new DateTimeImmutable($now)));
    }
}
