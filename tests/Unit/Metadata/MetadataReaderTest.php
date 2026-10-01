<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Metadata;

use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Exception\UnknownEndpoint;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Validation\TimeBounds;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Dsig\Exception\DigestMismatch;
use Beffroi\Xml\Dsig\Exception\InvalidKey;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use function str_repeat;
use function str_replace;

/**
 * Section 5.6, section 6.5: a peer's md:EntityDescriptor read strictly, where its keys come from (M-3) and where an
 * assertion may go (M-9); metadata rows of sections 9.2 and 9.3.
 */
final class MetadataReaderTest extends TestCase
{
    private const string NOW = '2026-09-30T12:00:00Z';

    /**
     * Section 6.5, SAML Metadata §2.4.3: an identity provider's metadata, every field read.
     */
    #[Test]
    public function itReadsAnIdentityProvider(): void
    {
        // Given
        $document = MetadataFixtures::load('behaviour/metadata-identity-provider.xml');

        // When
        $descriptor = $this->reader()->readTrusted($document);

        // Then
        static::assertEquals(
            new EntityDescriptor('https://idp.example.com/saml', null, new IdentityProvider(
                'https://idp.example.com/saml',
                [MetadataFixtures::certificate('idp')],
                [MetadataFixtures::certificate('sp')],
                [
                    new Endpoint(Binding::HttpRedirect, 'https://idp.example.com/saml/sso'),
                    new Endpoint(Binding::HttpPost, 'https://idp.example.com/saml/sso'),
                ],
                [new Endpoint(Binding::HttpRedirect, 'https://idp.example.com/saml/slo')],
                [NameIdFormat::Persistent],
                true,
            )),
            $descriptor,
        );
    }

    /**
     * Section 6.5, SAML Metadata §2.4.4: a service provider's metadata, every field read.
     */
    #[Test]
    public function itReadsAServiceProvider(): void
    {
        // Given
        $document = MetadataFixtures::load('behaviour/metadata-service-provider.xml');

        // When
        $descriptor = $this->reader()->readTrusted($document);

        // Then
        static::assertEquals(
            new EntityDescriptor('https://sp.example.com/saml', null, null, new ServiceProvider(
                'https://sp.example.com/saml',
                [MetadataFixtures::certificate('sp')],
                [MetadataFixtures::certificate('sp')],
                new IndexedEndpoints([
                    new IndexedEndpoint(Binding::HttpPost, 'https://sp.example.com/saml/acs', 0, true),
                    new IndexedEndpoint(Binding::HttpPost, 'https://sp.example.com/saml/acs/other', 1),
                ]),
                [new Endpoint(Binding::HttpPost, 'https://sp.example.com/saml/slo')],
                [NameIdFormat::Transient],
                true,
                true,
            )),
            $descriptor,
        );
    }

    /**
     * Section 9.3 row "a metadata listing Artifact and SOAP endpoints next to POST and Redirect ones", section 6.5
     * step 6: it loads, the HTTP-Redirect and HTTP-POST endpoints kept in order, the assertion consumer services on
     * HTTP-POST only.
     */
    #[Test]
    public function itKeepsTheRedirectAndPostEndpointsOnly(): void
    {
        // Given
        $document = MetadataFixtures::load('behaviour/metadata-artifact-and-soap-endpoints-next-to-post-and-redirect.xml');

        // When
        $descriptor = $this->reader()->readTrusted($document);

        // Then
        static::assertEquals(
            [
                [
                    new Endpoint(Binding::HttpRedirect, 'https://idp.example.com/saml/sso/redirect'),
                    new Endpoint(Binding::HttpPost, 'https://idp.example.com/saml/sso/post'),
                ],
                [
                    new Endpoint(Binding::HttpPost, 'https://idp.example.com/saml/slo/post'),
                    new Endpoint(
                        Binding::HttpRedirect,
                        'https://idp.example.com/saml/slo/redirect',
                        'https://idp.example.com/saml/slo/response',
                    ),
                ],
                [new IndexedEndpoint(Binding::HttpPost, 'https://idp.example.com/saml/acs/post', 1)],
                [],
            ],
            [
                $descriptor->identityProvider?->singleSignOnServices,
                $descriptor->identityProvider?->singleLogoutServices,
                $descriptor->serviceProvider?->assertionConsumerServices->endpoints,
                $descriptor->serviceProvider?->singleLogoutServices,
            ],
        );
    }

    /**
     * Section 6.5 step 4: the children a role may hold and the package does not use are skipped in their place of
     * the schema's order, Keycloak's md:ArtifactResolutionService among them.
     */
    #[Test]
    public function itSkipsTheOtherChildrenOfARole(): void
    {
        // Given
        $document = MetadataFixtures::load('behaviour/metadata-other-children-of-a-role-skipped.xml');

        // When
        $descriptor = $this->reader()->readTrusted($document);

        // Then
        static::assertEquals(
            [
                [MetadataFixtures::certificate('idp')],
                [NameIdFormat::Persistent],
                2,
                [MetadataFixtures::certificate('sp')],
                2,
            ],
            [
                $descriptor->identityProvider?->signingCertificates,
                $descriptor->identityProvider?->nameIdFormats,
                \count($descriptor->identityProvider->singleSignOnServices ?? []),
                $descriptor->serviceProvider?->signingCertificates,
                \count($descriptor->serviceProvider->assertionConsumerServices->endpoints ?? []),
            ],
        );
    }

    /**
     * Section 6.5 step 6, Keycloak's broker: an assertion consumer service on HTTP-Redirect, isDefault or not, is
     * dropped, and the default of SAML Metadata §2.2.3 applies over the kept ones.
     */
    #[Test]
    public function itResolvesTheDefaultOverTheKeptAssertionConsumerServices(): void
    {
        // Given
        $document = MetadataFixtures::load('behaviour/metadata-redirect-assertion-consumer-service-default-dropped.xml');

        // When
        $assertionConsumers = $this->reader()->readTrusted($document)->serviceProvider?->assertionConsumerServices;

        // Then
        static::assertEquals(
            [
                new IndexedEndpoint(Binding::HttpPost, 'https://sp.example.com/saml/acs', 2, false),
                new IndexedEndpoint(Binding::HttpPost, 'https://sp.example.com/saml/acs', 3),
            ],
            $assertionConsumers?->endpoints,
        );
        static::assertSame(3, $assertionConsumers?->default()->index);
    }

    /**
     * Section 6.5 step 6: byIndex() searches the kept assertion consumer services only, an index of a dropped one
     * is unknown (M-9).
     */
    #[Test]
    public function itDoesNotFindADroppedAssertionConsumerService(): void
    {
        // Given
        $assertionConsumers = $this->reader()
            ->readTrusted(MetadataFixtures::load('behaviour/metadata-redirect-assertion-consumer-service-default-dropped.xml'))
            ->serviceProvider
            ->assertionConsumerServices ?? static::fail('The metadata holds a service provider.');

        // Then
        $this->expectException(UnknownEndpoint::class);
        $this->expectExceptionMessageIs('No assertion consumer service of the metadata has that index (M-9).');

        // When
        $assertionConsumers->byIndex(1);
    }

    /**
     * Section 6.5 step 7: the formats of SAML Core §8.3 are kept, an empty one, an unknown one and one with a space
     * before it dropped.
     */
    #[Test]
    public function itDropsTheEmptyAndUnknownFormats(): void
    {
        // Given
        $document = MetadataFixtures::load('behaviour/metadata-empty-and-unknown-name-id-formats-dropped.xml');

        // When
        $descriptor = $this->reader()->readTrusted($document);

        // Then
        static::assertSame(
            [NameIdFormat::Transient, NameIdFormat::EmailAddress],
            $descriptor->identityProvider?->nameIdFormats,
        );
    }

    /**
     * Section 6.5 step 5, SAML Metadata §2.4.1.1 and E68: a key without use serves signing and encryption.
     */
    #[Test]
    public function itUsesAKeyWithoutUseForBoth(): void
    {
        // Given
        $document = MetadataFixtures::load('behaviour/metadata-key-without-use-serves-both.xml');

        // When
        $idp = $this->reader()->readTrusted($document)->identityProvider;

        // Then
        static::assertSame(
            [
                [MetadataFixtures::certificate('idp')],
                [MetadataFixtures::certificate('sp'), MetadataFixtures::certificate('idp')],
            ],
            [$idp?->signingCertificates, $idp?->encryptionCertificates],
        );
    }

    /**
     * Section 6.5 step 5, Metadata Interoperability Profile §2.5.1: ds:KeyName, ds:KeyValue, ds:RetrievalMethod and
     * the other children of ds:X509Data are hints that are not read; the md:EncryptionMethod URIs are checked and
     * not kept.
     */
    #[Test]
    public function itReadsTheCertificateAndNotTheHints(): void
    {
        // Given
        $document = MetadataFixtures::load('behaviour/metadata-key-info-hints-not-read.xml');

        // When
        $idp = $this->reader()->readTrusted($document)->identityProvider;

        // Then
        static::assertSame([MetadataFixtures::certificate('idp')], $idp?->signingCertificates);
    }

    /**
     * Section 6.5 step 5: a certificate written over several lines, which base64Binary allows, is kept on one.
     */
    #[Test]
    public function itKeepsACertificateOnOneLine(): void
    {
        // Given
        $document = MetadataFixtures::load('behaviour/metadata-certificate-over-several-lines.xml');

        // When
        $idp = $this->reader()->readTrusted($document)->identityProvider;

        // Then
        static::assertSame([MetadataFixtures::certificate('idp')], $idp?->signingCertificates);
    }

    /**
     * Section 6.5 step 4: the roles that do not list SAML 2.0, the other role descriptors, md:Extensions,
     * md:Organization, md:ContactPerson and md:AdditionalMetadataLocation are skipped; the one identity provider for
     * SAML 2.0 is read.
     */
    #[Test]
    public function itIgnoresTheRolesWithoutSaml2(): void
    {
        // Given
        $document = MetadataFixtures::load('behaviour/metadata-roles-without-saml2-ignored.xml');

        // When
        $descriptor = $this->reader()->readTrusted($document);

        // Then
        static::assertSame(
            [[MetadataFixtures::certificate('idp')], null],
            [$descriptor->identityProvider?->signingCertificates, $descriptor->serviceProvider],
        );
    }

    /**
     * M-7, section 6.5 step 3, section 9.3 row "the edges of M-7": a validUntil one second after now minus the skew
     * is still valid, and returned.
     */
    #[Test]
    #[DataProvider('provideClocksWithinValidUntil')]
    public function itAcceptsAValidUntilAfterNowMinusTheSkew(string $now, int $skew): void
    {
        // Given
        $reader = new MetadataReader(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable($now)),
            new TimeBounds(clockSkew: $skew),
        );

        // When
        $descriptor = $reader->readTrusted(MetadataFixtures::load('behaviour/metadata-valid-until.xml'));

        // Then
        static::assertEquals(new DateTimeImmutable('2026-10-01T00:00:00Z'), $descriptor->validUntil);
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideClocksWithinValidUntil(): iterable
    {
        yield 'the default skew, one second before the edge' => ['2026-10-01T00:02:59Z', 180];
        yield 'a skew of one second, at validUntil' => ['2026-10-01T00:00:00Z', 1];
    }

    /**
     * M-7, section 9.2 row "validUntil passed": a validUntil at or before now minus the skew is refused.
     */
    #[Test]
    #[DataProvider('provideClocksPastValidUntil')]
    public function itRefusesAValidUntilAtOrBeforeNowMinusTheSkew(string $path, string $now, int $skew): void
    {
        // Given
        $reader = new MetadataReader(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable($now)),
            new TimeBounds(clockSkew: $skew),
        );

        // Then
        $this->expectException(OutsideValidityWindow::class);
        $this->expectExceptionMessageIs('The metadata is past its validUntil (M-7).');

        // When
        $reader->readTrusted(MetadataFixtures::load($path));
    }

    /**
     * @return iterable<string, array{string, string, int}>
     */
    public static function provideClocksPastValidUntil(): iterable
    {
        yield 'passed a month ago' => ['hostile/metadata-valid-until-passed-refused.xml', self::NOW, 180];
        yield 'the default skew, at the edge' => ['behaviour/metadata-valid-until.xml', '2026-10-01T00:03:00Z', 180];
        yield 'a skew of one second, at the edge' => ['behaviour/metadata-valid-until.xml', '2026-10-01T00:00:01Z', 1];
    }

    /**
     * M-7, section 6.5 step 4, section 9.2 row "validUntil passed": the validUntil of a role that is read, one second
     * after now minus the skew, holds, as the entity's does.
     */
    #[Test]
    #[DataProvider('provideClocksWithinValidUntil')]
    public function itAcceptsARoleBeforeItsValidUntil(string $now, int $skew): void
    {
        // Given
        $reader = new MetadataReader(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable($now)),
            new TimeBounds(clockSkew: $skew),
        );

        // When
        $descriptor = $reader->readTrusted(MetadataFixtures::load('behaviour/adversarial-metadata-role-valid-until-accepted.xml'));

        // Then
        static::assertSame('https://idp.example.com/saml', $descriptor->identityProvider?->entityId);
    }

    /**
     * M-7, section 6.5 step 4, section 9.2 row "validUntil passed": a role that is read, at or before its own
     * validUntil minus the skew, refuses the metadata rather than being dropped.
     */
    #[Test]
    #[DataProvider('provideRolesPastValidUntil')]
    public function itRefusesARolePastItsValidUntil(string $path, string $now, int $skew): void
    {
        // Given
        $reader = new MetadataReader(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable($now)),
            new TimeBounds(clockSkew: $skew),
        );

        // Then
        $this->expectException(OutsideValidityWindow::class);
        $this->expectExceptionMessageIs('A role of the metadata is past its validUntil (M-7).');

        // When
        $reader->readTrusted(MetadataFixtures::load($path));
    }

    /**
     * @return iterable<string, array{string, string, int}>
     */
    public static function provideRolesPastValidUntil(): iterable
    {
        yield 'an identity provider passed a month ago' => [
            'hostile/adversarial-metadata-identity-provider-valid-until-passed-refused.xml',
            self::NOW,
            180,
        ];
        yield 'a service provider passed a month ago' => [
            'hostile/adversarial-metadata-service-provider-valid-until-passed-refused.xml',
            self::NOW,
            180,
        ];
        yield 'the default skew, at the edge' => [
            'behaviour/adversarial-metadata-role-valid-until-accepted.xml',
            '2026-10-01T00:03:00Z',
            180,
        ];
        yield 'a skew of one second, at the edge' => [
            'behaviour/adversarial-metadata-role-valid-until-accepted.xml',
            '2026-10-01T00:00:01Z',
            1,
        ];
    }

    /**
     * Section 6.5 step 4: a role that is ignored, for SAML 1.1, or skipped, an md:AttributeAuthorityDescriptor, is not
     * read, its validUntil with it: the metadata is read with its one identity provider for SAML 2.0.
     */
    #[Test]
    public function itDoesNotReadTheValidUntilOfARoleItDoesNotRead(): void
    {
        // Given
        $document = MetadataFixtures::load('behaviour/adversarial-metadata-ignored-roles-valid-until-passed-accepted.xml');

        // When
        $descriptor = $this->reader()->readTrusted($document);

        // Then
        static::assertEquals(
            [
                new Endpoint(Binding::HttpRedirect, 'https://idp.example.com/saml/sso'),
                new Endpoint(Binding::HttpPost, 'https://idp.example.com/saml/sso'),
            ],
            $descriptor->identityProvider?->singleSignOnServices,
        );
    }

    /**
     * M-2, M-1, section 6.5 step 2: signed metadata verified with the pinned key is read from what the signature
     * covered, the same descriptor as the document read without verification.
     */
    #[Test]
    public function itReadsSignedMetadataVerifiedWithThePinnedKey(): void
    {
        // Given
        $document = MetadataFixtures::load('behaviour/metadata-signed-by-the-identity-provider.xml');

        // When
        $descriptor = $this->reader()->readSigned($document, MetadataFixtures::verificationKeys('idp'));

        // Then
        static::assertEquals($this->reader()->readTrusted($document), $descriptor);
    }

    /**
     * M-7: the clock is read once per call.
     */
    #[Test]
    public function itReadsTheClockOnce(): void
    {
        // Given
        $clock = $this->createMock(ClockInterface::class);
        $clock->expects(self::once())->method('now')->willReturn(new DateTimeImmutable(self::NOW));
        $reader = new MetadataReader(SamlLoader::create(), $clock);

        // When
        $descriptor = $reader->readSigned(
            MetadataFixtures::load('behaviour/metadata-signed-by-the-identity-provider.xml'),
            MetadataFixtures::verificationKeys('idp'),
        );

        // Then
        static::assertSame('https://idp.example.com/saml', $descriptor->entityId);
    }

    /**
     * M-2 names the one exception: readTrusted() does not verify, a signature that no longer holds included.
     */
    #[Test]
    public function itDoesNotVerifyTrustedMetadata(): void
    {
        // Given
        $document = MetadataFixtures::load('hostile/metadata-signed-then-altered-refused.xml');

        // When
        $idp = $this->reader()->readTrusted($document)->identityProvider;

        // Then
        static::assertSame('https://idp.example.com/saml/sso/altered', $idp?->singleSignOnServices[0]->location);
    }

    /**
     * M-2, M-3, section 9.2 rows "a signed metadata verified with a key not pinned" and the signed metadata altered:
     * Dsig's refusals, as they are (section 5.8).
     *
     * @param class-string<RefusedXml> $exception
     */
    #[Test]
    #[DataProvider('provideSignedMetadataRefused')]
    public function itRefusesSignedMetadataThatDoesNotVerify(
        string $path,
        string $key,
        string $exception,
        string $message,
    ): void {
        // Given
        $document = MetadataFixtures::load($path);

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->reader()->readSigned($document, MetadataFixtures::verificationKeys($key === 'sp' ? 'sp' : 'idp'));
    }

    /**
     * @return iterable<string, array{string, string, class-string<RefusedXml>, string}>
     */
    public static function provideSignedMetadataRefused(): iterable
    {
        yield 'verified with a key not pinned' => [
            'behaviour/metadata-signed-by-the-identity-provider.xml',
            'sp',
            SignatureMismatch::class,
            'No trusted key verifies the signature over SignedInfo (D-7, D-8).',
        ];
        yield 'altered after signing' => [
            'hostile/metadata-signed-then-altered-refused.xml',
            'idp',
            DigestMismatch::class,
            'The claimed element is not what was signed (D-8).',
        ];
    }

    /**
     * M-2, section 6.5 step 2: readSigned() refuses metadata without a signature, and one out of its place before
     * anything is verified.
     *
     * @param class-string<RefusedXml> $exception
     */
    #[Test]
    #[DataProvider('provideMetadataNotSignedAsRequired')]
    public function itRefusesMetadataNotSignedAsReadSignedRequires(
        string $path,
        string $exception,
        string $message,
    ): void {
        // Given
        $document = MetadataFixtures::load($path);

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->reader()->readSigned($document, MetadataFixtures::verificationKeys('idp'));
    }

    /**
     * @return iterable<string, array{string, class-string<RefusedXml>, string}>
     */
    public static function provideMetadataNotSignedAsRequired(): iterable
    {
        yield 'unsigned' => [
            'behaviour/metadata-identity-provider.xml',
            SignatureRequired::class,
            'The metadata carries no ds:Signature as the first child of its root (M-2).',
        ];
        yield 'the signature after the role' => [
            'hostile/metadata-signature-not-first-refused.xml',
            MalformedMessage::class,
            'An md:EntityDescriptor holds a child the schema does not allow there, or out of its order (M-5).',
        ];
        yield 'md:EntitiesDescriptor' => [
            'hostile/metadata-entities-descriptor-refused.xml',
            Unsupported::class,
            'md:EntitiesDescriptor, aggregated metadata, is not supported (section 8).',
        ];
    }

    /**
     * Sections 9.2 and 8, M-5, M-13, M-17: each hostile metadata, one change from a valid one, refused with the
     * named exception and the rule in its message, never a value of the input (M-16).
     *
     * @param class-string<RefusedXml> $exception
     */
    #[Test]
    #[DataProvider('provideHostileMetadata')]
    public function itRefusesHostileMetadata(string $fixture, string $exception, string $message): void
    {
        // Given
        $document = MetadataFixtures::load('hostile/metadata-' . $fixture . '-refused.xml');

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->reader()->readTrusted($document);
    }

    /**
     * @return iterable<string, array{string, class-string<RefusedXml>, string}>
     */
    public static function provideHostileMetadata(): iterable
    {
        yield 'md:EntitiesDescriptor (section 9.2)' => [
            'entities-descriptor',
            Unsupported::class,
            'md:EntitiesDescriptor, aggregated metadata, is not supported (section 8).',
        ];
        yield 'two md:IDPSSODescriptor (section 9.2)' => [
            'two-identity-provider-roles',
            MalformedMessage::class,
            'An md:EntityDescriptor holds more than one md:IDPSSODescriptor for SAML 2.0 (section 6.5).',
        ];
        yield 'two md:SPSSODescriptor' => [
            'two-service-provider-roles',
            MalformedMessage::class,
            'An md:EntityDescriptor holds more than one md:SPSSODescriptor for SAML 2.0 (section 6.5).',
        ];
        yield 'seventeen signing certificates (section 9.2)' => [
            'seventeen-signing-certificates',
            LimitExceeded::class,
            'A role descriptor holds more than 16 md:KeyDescriptor for signing, the bound of section 7 (M-17).',
        ];
        yield 'seventeen encryption certificates' => [
            'seventeen-encryption-certificates',
            LimitExceeded::class,
            'A role descriptor holds more than 16 md:KeyDescriptor for encryption, the bound of section 7 (M-17).',
        ];
        yield 'sixty-five single sign-on services, two of them SOAP' => [
            'sixty-five-single-sign-on-services',
            LimitExceeded::class,
            'A role descriptor holds more than 64 md:SingleSignOnService, the bound of section 7 (M-17).',
        ];
        yield 'sixty-five single logout services, one of them Artifact' => [
            'sixty-five-single-logout-services',
            LimitExceeded::class,
            'A role descriptor holds more than 64 md:SingleLogoutService, the bound of section 7 (M-17).',
        ];
        yield 'sixty-five assertion consumer services, one of them Artifact' => [
            'sixty-five-assertion-consumer-services',
            LimitExceeded::class,
            'A role descriptor holds more than 64 md:AssertionConsumerService, the bound of section 7 (M-17).',
        ];
        yield 'seventeen NameID formats, one of them unknown' => [
            'seventeen-name-id-formats',
            LimitExceeded::class,
            'A role descriptor holds more than 16 md:NameIDFormat, the bound of section 7 (M-17).',
        ];
        yield 'a duplicate index (section 9.2)' => [
            'duplicate-index',
            MalformedMessage::class,
            'Two md:AssertionConsumerService of a role share an index (section 6.5).',
        ];
        yield 'a duplicate index, one of the two dropped' => [
            'duplicate-index-of-a-dropped-endpoint',
            MalformedMessage::class,
            'Two md:AssertionConsumerService of a role share an index (section 6.5).',
        ];
        yield 'ds:KeyValue alone (section 8)' => [
            'key-value-alone',
            Unsupported::class,
            'A ds:KeyInfo holds a ds:KeyValue and no certificate (section 8).',
        ];
        yield 'a ds:KeyInfo without ds:X509Data' => [
            'key-info-without-x509-data',
            MalformedMessage::class,
            'A ds:KeyInfo holds no ds:X509Data (section 6.5).',
        ];
        yield 'two ds:X509Data' => [
            'two-x509-data',
            MalformedMessage::class,
            'A ds:KeyInfo holds more than one ds:X509Data (section 6.5).',
        ];
        yield 'a ds:X509Data with two certificates' => [
            'x509-data-with-two-certificates',
            MalformedMessage::class,
            'A ds:X509Data holds no ds:X509Certificate, or more than one (section 6.5).',
        ];
        yield 'a ds:X509Data without certificate' => [
            'x509-data-without-certificate',
            MalformedMessage::class,
            'A ds:X509Data holds no ds:X509Certificate, or more than one (section 6.5).',
        ];
        yield 'an md:KeyDescriptor without ds:KeyInfo' => [
            'key-descriptor-without-key-info',
            MalformedMessage::class,
            'An md:KeyDescriptor holds no ds:KeyInfo (M-5).',
        ];
        yield 'a certificate of an RSA key of 1024 bits' => [
            'rsa-1024-signing-certificate',
            InvalidKey::class,
            'A verification key is RSA of at least 2048 bits (D-16).',
        ];
        yield 'an md:EncryptionMethod without Algorithm' => [
            'encryption-method-without-algorithm',
            MalformedMessage::class,
            'An md:EncryptionMethod has no Algorithm (M-5).',
        ];
        yield 'a root that is not md:EntityDescriptor' => [
            'root-not-entity-descriptor',
            MalformedMessage::class,
            'The root of the metadata is not an md:EntityDescriptor (section 6.5).',
        ];
        yield 'no entityID' => [
            'entity-descriptor-without-entity-id',
            MalformedMessage::class,
            'An md:EntityDescriptor has no entityID (M-5).',
        ];
        yield 'md:Extensions after a role' => [
            'extensions-after-a-role',
            MalformedMessage::class,
            'An md:EntityDescriptor holds a child the schema does not allow there, or out of its order (M-5).',
        ];
        yield 'two md:Extensions' => [
            'two-extensions',
            MalformedMessage::class,
            'An md:EntityDescriptor holds more than one md:Extensions (M-5).',
        ];
        yield 'an unknown md: element in a role' => [
            'unknown-metadata-element',
            MalformedMessage::class,
            'An md:IDPSSODescriptor holds a child the schema does not allow there, or out of its order (M-5).',
        ];
        yield 'an element of another namespace in a role' => [
            'element-of-another-namespace-in-a-role',
            MalformedMessage::class,
            'An md:IDPSSODescriptor holds a child the schema does not allow there, or out of its order (M-5).',
        ];
        yield 'roles and an md:AffiliationDescriptor' => [
            'roles-and-affiliation',
            MalformedMessage::class,
            'An md:EntityDescriptor holds role descriptors and an md:AffiliationDescriptor (M-5).',
        ];
        yield 'an md:AffiliationDescriptor alone' => [
            'affiliation-alone',
            MalformedMessage::class,
            'An md:EntityDescriptor holds no md:IDPSSODescriptor and no md:SPSSODescriptor for SAML 2.0 (M-13).',
        ];
        yield 'no role for SAML 2.0' => [
            'no-saml2-role',
            MalformedMessage::class,
            'An md:EntityDescriptor holds no md:IDPSSODescriptor and no md:SPSSODescriptor for SAML 2.0 (M-13).',
        ];
        yield 'a role without protocolSupportEnumeration' => [
            'role-without-protocol-support-enumeration',
            MalformedMessage::class,
            'An md:IDPSSODescriptor has no protocolSupportEnumeration (M-5).',
        ];
        yield 'an identity provider without single sign-on service' => [
            'identity-provider-without-single-sign-on-service',
            MalformedMessage::class,
            'An md:IDPSSODescriptor holds no md:SingleSignOnService (M-5).',
        ];
        yield 'an identity provider with Artifact and SOAP single sign-on services only' => [
            'identity-provider-with-artifact-and-soap-single-sign-on-only',
            MalformedMessage::class,
            'The md:IDPSSODescriptor lists no md:SingleSignOnService on HTTP-Redirect or HTTP-POST (section 6.5).',
        ];
        yield 'a service provider without assertion consumer service' => [
            'service-provider-without-assertion-consumer-service',
            MalformedMessage::class,
            'An md:SPSSODescriptor holds no md:AssertionConsumerService (M-5).',
        ];
        yield 'a service provider with HTTP-Redirect and Artifact assertion consumer services only' => [
            'service-provider-with-redirect-assertion-consumer-service-only',
            MalformedMessage::class,
            'The md:SPSSODescriptor lists no md:AssertionConsumerService on HTTP-POST (section 6.5).',
        ];
        yield 'an endpoint without Binding' => [
            'endpoint-without-binding',
            MalformedMessage::class,
            'An md:SingleSignOnService has no Binding (M-5).',
        ];
        yield 'an endpoint without Location' => [
            'endpoint-without-location',
            MalformedMessage::class,
            'An md:SingleSignOnService has no Location (M-5).',
        ];
        yield 'an assertion consumer service without index' => [
            'assertion-consumer-service-without-index',
            MalformedMessage::class,
            'An md:AssertionConsumerService has no index (M-5).',
        ];
        yield 'an assertion consumer service without Location' => [
            'assertion-consumer-service-without-location',
            MalformedMessage::class,
            'An md:AssertionConsumerService has no Location (M-5).',
        ];
        yield 'the signature after the role' => [
            'signature-not-first',
            MalformedMessage::class,
            'An md:EntityDescriptor holds a child the schema does not allow there, or out of its order (M-5).',
        ];
    }

    /**
     * M-5, M-6: a value not of its lexical form, one change from a valid metadata.
     *
     * @param class-string<RefusedXml> $exception
     */
    #[Test]
    #[DataProvider('provideValuesNotOfTheirForm')]
    public function itRefusesAValueNotOfItsForm(
        string $fixture,
        string $search,
        string $replace,
        string $exception,
        string $message,
    ): void {
        // Given
        $document = SamlLoader::create()->load(str_replace(
            $search,
            $replace,
            MetadataFixtures::bytes('behaviour/metadata-' . $fixture . '.xml'),
        ));

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($message);

        // When
        $this->reader()->readTrusted($document);
    }

    /**
     * @return iterable<string, array{string, string, string, class-string<RefusedXml>, string}>
     */
    public static function provideValuesNotOfTheirForm(): iterable
    {
        $entityId = 'entityID="https://idp.example.com/saml"';
        $index = 'index="1"';
        $post = 'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/saml/sso"';
        $uri = 'A URI is not absolute (M-6).';
        $boolean = 'A boolean is not one of true, false, 1 and 0 (M-6).';
        $unsignedShort = 'An md:AssertionConsumerService index is not an xs:unsignedShort without sign or leading zero (M-6).';
        yield 'a relative entityID' => [
            'identity-provider',
            $entityId,
            'entityID="idp"',
            MalformedMessage::class,
            $uri,
        ];
        yield 'an entityID of 1025 characters (section 9.2)' => [
            'identity-provider',
            $entityId,
            'entityID="https://' . str_repeat('a', 1017) . '"',
            MalformedMessage::class,
            'A URI is longer than 1024 characters (M-6).',
        ];
        yield 'a validUntil without Z' => [
            'identity-provider',
            $entityId,
            $entityId . ' validUntil="2026-10-01T00:00:00"',
            MalformedMessage::class,
            'A time is not an xs:dateTime in UTC with the Z designator (M-6).',
        ];
        yield 'a validUntil of a role without Z (section 6.5 step 4)' => [
            'identity-provider',
            'protocolSupportEnumeration=',
            'validUntil="2026-10-01T00:00:00" protocolSupportEnumeration=',
            MalformedMessage::class,
            'A time is not an xs:dateTime in UTC with the Z designator (M-6).',
        ];
        yield 'a use of both' => [
            'identity-provider',
            'use="signing"',
            'use="both"',
            MalformedMessage::class,
            'An md:KeyDescriptor use is not signing or encryption (M-5).',
        ];
        yield 'an empty use' => [
            'identity-provider',
            'use="encryption"',
            'use=""',
            MalformedMessage::class,
            'An md:KeyDescriptor use is not signing or encryption (M-5).',
        ];
        yield 'a relative EncryptionMethod Algorithm' => [
            'key-info-hints-not-read',
            'Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"',
            'Algorithm="rsa-oaep"',
            MalformedMessage::class,
            $uri,
        ];
        yield 'a relative Binding' => [
            'identity-provider',
            $post,
            'Binding="HTTP-POST" Location="https://idp.example.com/saml/sso"',
            MalformedMessage::class,
            $uri,
        ];
        yield 'a relative Location' => [
            'identity-provider',
            $post,
            'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="/saml/sso"',
            MalformedMessage::class,
            $uri,
        ];
        yield 'a relative ResponseLocation' => [
            'identity-provider',
            'Location="https://idp.example.com/saml/slo"',
            'Location="https://idp.example.com/saml/slo" ResponseLocation="slo"',
            MalformedMessage::class,
            $uri,
        ];
        yield 'a relative assertion consumer service Binding' => [
            'service-provider',
            'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/acs/other"',
            'Binding="HTTP-POST" Location="https://sp.example.com/saml/acs/other"',
            MalformedMessage::class,
            $uri,
        ];
        yield 'a relative assertion consumer service Location' => [
            'service-provider',
            'Location="https://sp.example.com/saml/acs/other"',
            'Location="acs"',
            MalformedMessage::class,
            $uri,
        ];
        foreach (['01', '+1', '-1', ' 1', '1 ', '', '1.0', 'one', '65536', '99999', '100000'] as $value) {
            yield 'an index of "' . $value . '"' => [
                'service-provider',
                $index,
                'index="' . $value . '"',
                MalformedMessage::class,
                $unsignedShort,
            ];
        }
        foreach (['TRUE', 'yes', ' true', ''] as $value) {
            yield 'an isDefault of "' . $value . '"' => [
                'service-provider',
                'isDefault="true"',
                'isDefault="' . $value . '"',
                MalformedMessage::class,
                $boolean,
            ];
            yield 'a WantAuthnRequestsSigned of "' . $value . '"' => [
                'identity-provider',
                'WantAuthnRequestsSigned="true"',
                'WantAuthnRequestsSigned="' . $value . '"',
                MalformedMessage::class,
                $boolean,
            ];
            yield 'an AuthnRequestsSigned of "' . $value . '"' => [
                'service-provider',
                'AuthnRequestsSigned="true"',
                'AuthnRequestsSigned="' . $value . '"',
                MalformedMessage::class,
                $boolean,
            ];
            yield 'a WantAssertionsSigned of "' . $value . '"' => [
                'service-provider',
                'WantAssertionsSigned="true"',
                'WantAssertionsSigned="' . $value . '"',
                MalformedMessage::class,
                $boolean,
            ];
        }
    }

    /**
     * M-6: an index is an xs:unsignedShort, its two ends included.
     */
    #[Test]
    #[DataProvider('provideIndexes')]
    public function itReadsAnIndex(string $index, int $expected): void
    {
        // Given
        $document = SamlLoader::create()->load(str_replace(
            'index="1"',
            'index="' . $index . '"',
            MetadataFixtures::bytes('behaviour/metadata-service-provider.xml'),
        ));

        // When
        $assertionConsumers = $this->reader()->readTrusted($document)->serviceProvider?->assertionConsumerServices;

        // Then
        static::assertSame($expected, $assertionConsumers?->endpoints[1]->index);
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideIndexes(): iterable
    {
        yield 'two' => ['2', 2];
        yield '65535' => ['65535', 65_535];
        yield 'ten thousand' => ['10000', 10_000];
    }

    /**
     * M-6, section 6.5 step 7: a flag is one of the four forms of a boolean, absent meaning false.
     */
    #[Test]
    #[DataProvider('provideFlags')]
    public function itReadsTheFlags(
        string $search,
        string $replace,
        bool $wantAuthnRequestsSigned,
        bool $authnRequestsSigned,
        bool $wantAssertionsSigned,
    ): void {
        // Given
        $idp = SamlLoader::create()->load(str_replace(
            $search,
            $replace,
            MetadataFixtures::bytes('behaviour/metadata-identity-provider.xml'),
        ));
        $sp = SamlLoader::create()->load(str_replace(
            $search,
            $replace,
            MetadataFixtures::bytes('behaviour/metadata-service-provider.xml'),
        ));

        // When
        $identityProvider = $this->reader()->readTrusted($idp)->identityProvider;
        $serviceProvider = $this->reader()->readTrusted($sp)->serviceProvider;

        // Then
        static::assertSame(
            [$wantAuthnRequestsSigned, $authnRequestsSigned, $wantAssertionsSigned],
            [
                $identityProvider?->wantAuthnRequestsSigned,
                $serviceProvider?->authnRequestsSigned,
                $serviceProvider?->wantAssertionsSigned,
            ],
        );
    }

    /**
     * @return iterable<string, array{string, string, bool, bool, bool}>
     */
    public static function provideFlags(): iterable
    {
        yield 'true' => ['="true"', '="true"', true, true, true];
        yield '1' => ['="true"', '="1"', true, true, true];
        yield 'false' => ['="true"', '="false"', false, false, false];
        yield '0' => ['="true"', '="0"', false, false, false];
        yield 'absent' => ['Signed="true"', 'Signed-not="true"', false, false, false];
    }

    private function reader(): MetadataReader
    {
        return new MetadataReader(SamlLoader::create(), new FrozenClock(new DateTimeImmutable(self::NOW)));
    }
}
