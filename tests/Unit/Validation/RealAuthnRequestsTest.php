<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Validation;

use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Protocol\NameIdPolicy;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 9.4: the AuthnRequest documents of tests/Fixture/real/, bytes as received, validated with a clock frozen at
 * their IssueInstant against the metadata their producers published in the same capture. A request the model refuses
 * is a finding (section 9.4): Keycloak 26.7.4's, under the rule of section 8 as it stands.
 */
final class RealAuthnRequestsTest extends TestCase
{
    private const string SIMPLESAMLPHP_SSO = 'http://localhost:8081/simplesaml/module.php/saml/idp/singleSignOnService';

    private const string SIMPLESAMLPHP_ACS = 'http://localhost:8082/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp';

    private const string KEYCLOAK_SSO = 'http://localhost:8180/realms/idp/protocol/saml';

    /**
     * Section 9.4, section 6.8: the AuthnRequest of SimpleSAMLphp 2.5.3.1's service provider, which HTTP-Redirect
     * carried with a signature over its query string that the capture verified under the service provider's metadata
     * (tests/Interop/simplesamlphp/README.md): accepted as authenticated by the binding, its assertion consumer service
     * the one of its URL.
     */
    #[Test]
    public function itAcceptsTheRequestOfSimpleSamlPhp(): void
    {
        // Given
        $request = AuthnRequestFixtures::load('real/simplesamlphp-2.5.3.1-sp-authnrequest-2026-09-30.xml');

        // When
        $accepted = $this->validator('2026-09-30T10:34:38Z')->validateAuthenticatedByBinding(
            $request,
            $this->serviceProvider('simplesamlphp-2.5.3.1-sp-metadata-2026-09-30.xml'),
            $this->identityProvider('simplesamlphp-2.5.3.1-idp-metadata-2026-09-30.xml'),
            self::SIMPLESAMLPHP_SSO,
        );

        // Then
        static::assertEquals(
            [
                new AuthnRequest(
                    '_8a3c5b08ae40d362750a2b17db4f78d18bdd9b369e',
                    new DateTimeImmutable('2026-09-30T10:34:38Z'),
                    new Issuer('http://localhost:8082/simplesaml/module.php/saml/sp/metadata/default-sp'),
                    self::SIMPLESAMLPHP_SSO,
                    self::SIMPLESAMLPHP_ACS,
                    null,
                    AuthnRequestFixtures::POST,
                ),
                0,
                self::SIMPLESAMLPHP_ACS,
                Authentication::Binding,
            ],
            [
                $accepted->request,
                $accepted->assertionConsumerService->index,
                $accepted->assertionConsumerService->location,
                $accepted->authentication,
            ],
        );
    }

    /**
     * Section 9.4, M-2, Profiles §4.1.6: the same request given to validate(), as if it had arrived without the
     * signature of its query string, is refused, since SimpleSAMLphp's metadata says AuthnRequestsSigned.
     */
    #[Test]
    public function itRefusesTheRequestOfSimpleSamlPhpWithoutTheSignatureOfItsBinding(): void
    {
        // Given
        $request = AuthnRequestFixtures::load('real/simplesamlphp-2.5.3.1-sp-authnrequest-2026-09-30.xml');

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The message carries no ds:Signature, which the profile requires (M-2).');

        // When
        $this->validator('2026-09-30T10:34:38Z')->validate(
            $request,
            $this->serviceProvider('simplesamlphp-2.5.3.1-sp-metadata-2026-09-30.xml'),
            $this->identityProvider('simplesamlphp-2.5.3.1-idp-metadata-2026-09-30.xml'),
            self::SIMPLESAMLPHP_SSO,
        );
    }

    /**
     * Section 9.4, M-2, M-3: the AuthnRequest simplesamlphp/saml2 4.20.3 signed with the service provider's test key,
     * in its HTTP-POST form, verified under the certificate of that service provider's metadata and not the one of
     * its KeyInfo; its NameIDPolicy returned.
     */
    #[Test]
    public function itAcceptsTheRequestTheSimpleSamlPhpLibrarySigned(): void
    {
        // Given
        $request = AuthnRequestFixtures::load('real/simplesamlphp-saml2-4.20.3-authnrequest-signed-2026-09-30.xml');

        // When
        $accepted = $this->validator('2026-09-30T11:59:55Z')->validate(
            $request,
            $this->serviceProvider('simplesamlphp-saml2-4.20.3-sp-metadata-2026-09-30.xml'),
            $this->identityProvider('simplesamlphp-saml2-4.20.3-idp-metadata-2026-09-30.xml'),
            'https://idp.example.org/sso',
        );

        // Then
        static::assertEquals(
            [
                new AuthnRequest(
                    '_ssp-lib-authnrequest-0001',
                    new DateTimeImmutable('2026-09-30T11:59:55Z'),
                    new Issuer('https://sp.example.org'),
                    'https://idp.example.org/sso',
                    'https://sp.example.org/acs',
                    null,
                    AuthnRequestFixtures::POST,
                    new NameIdPolicy(NameIdFormat::Transient->value, null, true),
                ),
                0,
                Authentication::XmlSignature,
            ],
            [$accepted->request, $accepted->assertionConsumerService->index, $accepted->authentication],
        );
    }

    /**
     * Section 9.4, section 8, finding F1 of tests/Interop/keycloak/README.md: the AuthnRequest of Keycloak 26.7.4's
     * broker asks for its response over HTTP-Redirect, and is refused by name under the rule as it stands, once its
     * assertion consumer service is resolved to the broker's HTTP-POST one. The identity provider is the model in the
     * place of Keycloak's realm idp, at its single sign-on service, not asking for signed requests as the installation's
     * client did not (saml.client.signature=false): the broker signs none under its defaults.
     */
    #[Test]
    public function itRefusesTheRequestOfKeycloakByItsProtocolBinding(): void
    {
        // Given
        $request = AuthnRequestFixtures::load('real/keycloak-26.7.4-sp-authn-request-2026-09-30.xml');
        $realm = $this->identityProvider('keycloak-26.7.4-idp-metadata-2026-09-30.xml');
        $self = new IdentityProvider(
            $realm->entityId,
            $realm->signingCertificates,
            $realm->encryptionCertificates,
            $realm->singleSignOnServices,
            $realm->singleLogoutServices,
            $realm->nameIdFormats,
            false,
        );

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs('The ProtocolBinding of an AuthnRequest is not HTTP-POST, the one binding the package answers over (section 8).');

        // When
        $this->validator('2026-09-30T10:27:55.895Z')->validate(
            $request,
            $this->serviceProvider('keycloak-26.7.4-sp-metadata-2026-09-30.xml'),
            $self,
            self::KEYCLOAK_SSO,
        );
    }

    /**
     * The validator, its clock frozen at the IssueInstant of the request.
     */
    private function validator(string $issueInstant): AuthnRequestValidator
    {
        return new AuthnRequestValidator(SamlLoader::create(), new FrozenClock(new DateTimeImmutable($issueInstant)));
    }

    private function serviceProvider(string $file): ServiceProvider
    {
        return (
            $this->metadata($file)->serviceProvider ?? throw new LogicException('The metadata holds a service provider.')
        );
    }

    private function identityProvider(string $file): IdentityProvider
    {
        return (
            $this->metadata($file)->identityProvider ?? throw new LogicException('The metadata holds an identity provider.')
        );
    }

    /**
     * The metadata of the same capture, read by readTrusted() at noon of its day (section 9.4).
     */
    private function metadata(string $file): EntityDescriptor
    {
        return new MetadataReader(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-09-30T12:00:00Z')),
        )->readTrusted(MetadataFixtures::load('real/' . $file));
    }
}
