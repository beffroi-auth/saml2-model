<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit;

use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function count;
use LogicException;
use function preg_replace;
use function sprintf;

/**
 * Section 9.4: the real documents of tests/Fixture/real/, bytes as received, read with a clock frozen at their
 * capture. A real document the model refuses is a finding (section 9.4); none of these is refused.
 */
final class RealDocumentsTest extends TestCase
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * Section 9.4, section 6.5: the metadata of an identity provider, as Entra, Keycloak 26.7.4 and SimpleSAMLphp
     * 2.5.3.1 publish it and as its library 4.20.3 writes it, read by readTrusted().
     *
     * @param list<Endpoint> $singleSignOn
     * @param list<Endpoint> $singleLogout
     * @param list<NameIdFormat> $formats
     */
    #[Test]
    #[DataProvider('provideIdentityProviders')]
    public function itReadsTheMetadataOfAnIdentityProvider(
        string $file,
        string $entityId,
        int $signing,
        int $encryption,
        array $singleSignOn,
        array $singleLogout,
        array $formats,
        bool $wantAuthnRequestsSigned,
    ): void {
        // Given
        $document = MetadataFixtures::load('real/' . $file);

        // When
        $descriptor = $this->reader($file)->readTrusted($document);

        // Then
        $idp = $descriptor->identityProvider;
        static::assertEquals(
            [
                $entityId,
                null,
                $signing,
                $encryption,
                $singleSignOn,
                $singleLogout,
                $formats,
                $wantAuthnRequestsSigned,
                null,
            ],
            [
                $descriptor->entityId,
                $descriptor->validUntil,
                count($idp->signingCertificates ?? []),
                count($idp->encryptionCertificates ?? []),
                $idp?->singleSignOnServices,
                $idp?->singleLogoutServices,
                $idp?->nameIdFormats,
                $idp?->wantAuthnRequestsSigned,
                $descriptor->serviceProvider,
            ],
        );
    }

    /**
     * @return iterable<string, array{string, string, int, int, list<Endpoint>, list<Endpoint>, list<NameIdFormat>, bool}>
     */
    public static function provideIdentityProviders(): iterable
    {
        $entra = 'https://login.microsoftonline.com/common/saml2';
        yield 'Entra, two RoleDescriptor skipped, six signing keys' => [
            'entra-common-federation-metadata-2026-09-23.xml',
            'https://sts.windows.net/{tenantid}/',
            6,
            0,
            [new Endpoint(Binding::HttpRedirect, $entra), new Endpoint(Binding::HttpPost, $entra)],
            [new Endpoint(Binding::HttpRedirect, $entra)],
            [],
            false,
        ];
        $keycloak = 'http://localhost:8180/realms/idp/protocol/saml';
        yield 'Keycloak, an md:ArtifactResolutionService skipped, SOAP and Artifact dropped' => [
            'keycloak-26.7.4-idp-metadata-2026-09-30.xml',
            'http://localhost:8180/realms/idp',
            1,
            0,
            [new Endpoint(Binding::HttpPost, $keycloak), new Endpoint(Binding::HttpRedirect, $keycloak)],
            [new Endpoint(Binding::HttpPost, $keycloak), new Endpoint(Binding::HttpRedirect, $keycloak)],
            [NameIdFormat::Persistent, NameIdFormat::Transient, NameIdFormat::Unspecified, NameIdFormat::EmailAddress],
            true,
        ];
        $simplesamlphp = 'http://localhost:8081/simplesaml/module.php/saml/idp/';
        yield 'SimpleSAMLphp, one certificate for signing and for encryption' => [
            'simplesamlphp-2.5.3.1-idp-metadata-2026-09-30.xml',
            'http://localhost:8081/simplesaml/module.php/saml/idp/metadata',
            1,
            1,
            [new Endpoint(Binding::HttpRedirect, $simplesamlphp . 'singleSignOnService')],
            [new Endpoint(Binding::HttpRedirect, $simplesamlphp . 'singleLogout')],
            [NameIdFormat::Transient],
            false,
        ];
        yield 'the SimpleSAMLphp library' => [
            'simplesamlphp-saml2-4.20.3-idp-metadata-2026-09-30.xml',
            'https://idp.example.org',
            1,
            0,
            [new Endpoint(Binding::HttpRedirect, 'https://idp.example.org/sso')],
            [new Endpoint(Binding::HttpRedirect, 'https://idp.example.org/slo')],
            [NameIdFormat::Transient],
            false,
        ];
    }

    /**
     * Section 9.4, section 6.5: the metadata of a service provider, as Keycloak 26.7.4's broker and SimpleSAMLphp
     * 2.5.3.1 publish it and as its library 4.20.3 writes it, read by readTrusted(); the default assertion consumer
     * service resolved over the HTTP-POST ones (M-9).
     *
     * @param list<IndexedEndpoint> $assertionConsumers
     * @param list<Endpoint> $singleLogout
     * @param list<NameIdFormat> $formats
     */
    #[Test]
    #[DataProvider('provideServiceProviders')]
    public function itReadsTheMetadataOfAServiceProvider(
        string $file,
        string $entityId,
        int $signing,
        int $encryption,
        array $assertionConsumers,
        int $default,
        array $singleLogout,
        array $formats,
        bool $authnRequestsSigned,
        bool $wantAssertionsSigned,
    ): void {
        // Given
        $document = MetadataFixtures::load('real/' . $file);

        // When
        $descriptor = $this->reader($file)->readTrusted($document);

        // Then
        $sp = $descriptor->serviceProvider;
        static::assertEquals(
            [
                $entityId,
                null,
                $signing,
                $encryption,
                $assertionConsumers,
                $default,
                $singleLogout,
                $formats,
                $authnRequestsSigned,
                $wantAssertionsSigned,
                null,
            ],
            [
                $descriptor->entityId,
                $descriptor->validUntil,
                count($sp->signingCertificates ?? []),
                count($sp->encryptionCertificates ?? []),
                $sp?->assertionConsumerServices->endpoints,
                $sp?->assertionConsumerServices->default()->index,
                $sp?->singleLogoutServices,
                $sp?->nameIdFormats,
                $sp?->authnRequestsSigned,
                $sp?->wantAssertionsSigned,
                $descriptor->identityProvider,
            ],
        );
    }

    /**
     * @return iterable<string, array{string, string, int, int, list<IndexedEndpoint>, int, list<Endpoint>, list<NameIdFormat>, bool, bool}>
     */
    public static function provideServiceProviders(): iterable
    {
        $keycloak = 'http://localhost:8180/realms/sp/broker/idp/endpoint';
        yield 'the Keycloak broker, its HTTP-Redirect default and its Artifact service dropped' => [
            'keycloak-26.7.4-sp-metadata-2026-09-30.xml',
            'http://localhost:8180/realms/sp',
            0,
            0,
            [new IndexedEndpoint(Binding::HttpPost, $keycloak, 2)],
            2,
            [new Endpoint(Binding::HttpRedirect, $keycloak), new Endpoint(Binding::HttpPost, $keycloak)],
            [NameIdFormat::Persistent],
            false,
            false,
        ];
        $simplesamlphp = 'http://localhost:8082/simplesaml/module.php/saml/sp/';
        yield 'SimpleSAMLphp, md:Extensions not read, its Artifact service dropped' => [
            'simplesamlphp-2.5.3.1-sp-metadata-2026-09-30.xml',
            'http://localhost:8082/simplesaml/module.php/saml/sp/metadata/default-sp',
            1,
            1,
            [new IndexedEndpoint(Binding::HttpPost, $simplesamlphp . 'saml2-acs.php/default-sp', 0)],
            0,
            [new Endpoint(Binding::HttpRedirect, $simplesamlphp . 'saml2-logout.php/default-sp')],
            [],
            true,
            false,
        ];
        yield 'the SimpleSAMLphp library' => [
            'simplesamlphp-saml2-4.20.3-sp-metadata-2026-09-30.xml',
            'https://sp.example.org',
            1,
            0,
            [new IndexedEndpoint(Binding::HttpPost, 'https://sp.example.org/acs', 0)],
            0,
            [new Endpoint(Binding::HttpRedirect, 'https://sp.example.org/slo')],
            [NameIdFormat::Transient],
            true,
            true,
        ];
    }

    /**
     * Section 9.4, M-2, M-1: the metadata the SimpleSAMLphp library signed with a test key, verified by
     * readSigned() under the certificate of that key, reads as its unsigned twin.
     */
    #[Test]
    #[DataProvider('provideSignedByTheLibrary')]
    public function itVerifiesTheMetadataTheLibrarySigned(string $signed, string $unsigned, string $key): void
    {
        // Given
        $document = MetadataFixtures::load('real/' . $signed);

        // When
        $descriptor = $this->reader($signed)->readSigned(
            $document,
            MetadataFixtures::verificationKeys($key === 'sp' ? 'sp' : 'idp'),
        );

        // Then
        static::assertEquals(
            $this->reader($unsigned)->readTrusted(MetadataFixtures::load('real/' . $unsigned)),
            $descriptor,
        );
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideSignedByTheLibrary(): iterable
    {
        yield 'an identity provider' => [
            'simplesamlphp-saml2-4.20.3-idp-metadata-signed-2026-09-30.xml',
            'simplesamlphp-saml2-4.20.3-idp-metadata-2026-09-30.xml',
            'idp',
        ];
        yield 'a service provider' => [
            'simplesamlphp-saml2-4.20.3-sp-metadata-signed-2026-09-30.xml',
            'simplesamlphp-saml2-4.20.3-sp-metadata-2026-09-30.xml',
            'sp',
        ];
    }

    /**
     * Section 9.4, M-2: Entra's metadata verified by readSigned() under the certificate of its own KeyInfo, which
     * proves the signature and not the trust, reads as by readTrusted().
     */
    #[Test]
    public function itVerifiesEntraMetadataUnderTheCertificateOfItsOwnKeyInfo(): void
    {
        // Given
        $file = 'entra-common-federation-metadata-2026-09-23.xml';
        $document = MetadataFixtures::load('real/' . $file);
        $certificate = $document->root();
        foreach (['Signature', 'KeyInfo', 'X509Data', 'X509Certificate'] as $local) {
            $certificate = Children::one($certificate, new Name(self::DSIG, $local));
        }
        $keys = new VerificationKeys([VerificationKey::fromCertificateBase64(Text::of($certificate))]);

        // When
        $descriptor = $this->reader($file)->readSigned($document, $keys);

        // Then
        static::assertEquals($this->reader($file)->readTrusted(MetadataFixtures::load('real/' . $file)), $descriptor);
    }

    /**
     * Section 9.4, section 6.1, M-2: the responses of real identity providers, validated with the clock frozen at
     * their IssueInstant, under the keys of the metadata that goes with each: SimpleSAMLphp 2.5.3.1's two captured
     * responses, its default signing the response and the assertion, the other the assertion only; Keycloak 26.7.4's,
     * the response only; and the two responses simplesamlphp/saml2 4.20.3, the code SimpleSAMLphp signs with, made on
     * 27 September 2026 under xml-security's test certificate (its tests/Dsig/Fixture/real/, copied byte for byte with
     * that certificate).
     */
    #[Test]
    #[DataProvider('provideRealResponses')]
    public function itAcceptsTheResponseOfARealIdentityProvider(
        string $file,
        IdentityProvider $idp,
        string $issueInstant,
        ExpectedResponse $expected,
        SignatureCoverage $coverage,
    ): void {
        // Given
        $response = UnverifiedResponse::of(MetadataFixtures::load('real/' . $file));
        $validator = new ResponseValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable($issueInstant)),
            new InMemoryReplayGuard(),
        );

        // When
        $accepted = $validator->validate($response, $idp, $expected);

        // Then
        static::assertSame($coverage, $accepted->coverage);
    }

    /**
     * @return iterable<string, array{string, IdentityProvider, string, ExpectedResponse, SignatureCoverage}>
     */
    public static function provideRealResponses(): iterable
    {
        $simplesamlphp = self::identityProviderOf('simplesamlphp-2.5.3.1-idp-metadata-2026-09-30.xml');
        $acs = 'http://localhost:8082/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp';
        $sp = 'http://localhost:8082/simplesaml/module.php/saml/sp/metadata/default-sp';
        yield 'SimpleSAMLphp 2.5.3.1 by default, the response and the assertion signed' => [
            'simplesamlphp-2.5.3.1-idp-response-signed-both-2026-09-30.xml',
            $simplesamlphp,
            '2026-09-30T10:34:38Z',
            ExpectedResponse::toRequest('_8a3c5b08ae40d362750a2b17db4f78d18bdd9b369e', $acs, $sp),
            SignatureCoverage::AssertionAndResponse,
        ];
        yield 'SimpleSAMLphp 2.5.3.1 configured to sign the assertion only' => [
            'simplesamlphp-2.5.3.1-idp-response-signed-assertion-2026-09-30.xml',
            $simplesamlphp,
            '2026-09-30T10:34:41Z',
            ExpectedResponse::toRequest('_7cc71f776e69f4f4cdb3fba9ebc8392b9491d4e6e4', $acs, $sp),
            SignatureCoverage::Assertion,
        ];
        yield 'Keycloak 26.7.4 by default, the response signed' => [
            'keycloak-26.7.4-idp-response-2026-09-30.xml',
            self::identityProviderOf('keycloak-26.7.4-idp-metadata-2026-09-30.xml'),
            '2026-09-30T10:27:56.331Z',
            ExpectedResponse::toRequest(
                'ID_92e2f605-6fee-4dd0-bf79-5a66eb3dc449',
                'http://localhost:8180/realms/sp/broker/idp/endpoint',
                'http://localhost:8180/realms/sp',
            ),
            SignatureCoverage::Response,
        ];
        $library = new IdentityProvider(
            'https://idp.example.org',
            [(string) preg_replace(
                '~-----[A-Z ]+-----|\s+~',
                '',
                MetadataFixtures::bytes('real/xml-security-test-signing-certificate.pem'),
            )],
            [],
            [new Endpoint(Binding::HttpRedirect, 'https://idp.example.org/sso')],
        );
        $expected = ExpectedResponse::toRequest(
            '_request-7g8h9i',
            'https://sp.example.org/acs',
            'https://sp.example.org',
        );
        yield 'simplesamlphp/saml2 4.20.3, the assertion signed' => [
            'simplesamlphp-saml2-4.20.3-response-signed-assertion-2026-09-27.xml',
            $library,
            '2026-09-27T10:00:00Z',
            $expected,
            SignatureCoverage::Assertion,
        ];
        yield 'simplesamlphp/saml2 4.20.3, the response and the assertion signed' => [
            'simplesamlphp-saml2-4.20.3-response-signed-both-2026-09-27.xml',
            $library,
            '2026-09-27T10:00:00Z',
            $expected,
            SignatureCoverage::AssertionAndResponse,
        ];
    }

    /**
     * The identity provider of a real metadata of tests/Fixture/real/, read by readTrusted().
     */
    private static function identityProviderOf(string $file): IdentityProvider
    {
        $date = preg_match('~(\d{4}-\d{2}-\d{2})\.xml\z~', $file, $parts) === 1 ? $parts[1] : '';
        return (
            new MetadataReader(
                SamlLoader::create(),
                new FrozenClock(new DateTimeImmutable($date . 'T12:00:00Z')),
            )->readTrusted(MetadataFixtures::load('real/' . $file))->identityProvider ?? throw new LogicException(sprintf(
                '%s holds no identity provider.',
                $file,
            ))
        );
    }

    /**
     * The clock frozen at noon UTC of the capture date the name of the file carries (section 9.4).
     */
    private function reader(string $file): MetadataReader
    {
        $date = preg_match('~(\d{4}-\d{2}-\d{2})\.xml\z~', $file, $parts) === 1 ? $parts[1] : '';

        return new MetadataReader(SamlLoader::create(), new FrozenClock(new DateTimeImmutable($date . 'T12:00:00Z')));
    }
}
