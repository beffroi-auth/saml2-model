<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Metadata;

use function array_fill;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Metadata\RoleRules;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Xml\Dsig\Exception\InvalidKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3: the rules an identity provider and a service provider share, whoever builds them: an entity ID of
 * M-6, the counts of section 7 (M-17), each certificate an RSA key of at least 2048 bits (D-16).
 */
final class RoleRulesTest extends TestCase
{
    /**
     * Section 7: every list at its bound.
     */
    #[Test]
    public function itAcceptsEveryListAtItsBound(): void
    {
        // Then
        $this->expectNotToPerformAssertions();

        // When
        RoleRules::check(
            'https://idp.example.com',
            array_fill(0, 16, MetadataFixtures::certificate('idp')),
            array_fill(0, 16, MetadataFixtures::certificate('sp')),
            array_fill(0, 64, new Endpoint(Binding::HttpRedirect, 'https://idp.example.com/slo')),
            array_fill(0, 16, NameIdFormat::Transient),
        );
    }

    /**
     * M-17, section 9.2 row "seventeen signing certificates" and "one over each bound of section 7".
     *
     * @param list<string> $signing
     * @param list<string> $encryption
     * @param list<Endpoint> $singleLogout
     * @param list<NameIdFormat> $formats
     */
    #[Test]
    #[DataProvider('provideListsOverTheirBound')]
    public function itRefusesAListOverItsBound(
        array $signing,
        array $encryption,
        array $singleLogout,
        array $formats,
        string $message,
    ): void {
        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs($message);

        // When
        RoleRules::check('https://idp.example.com', $signing, $encryption, $singleLogout, $formats);
    }

    /**
     * @return iterable<string, array{list<string>, list<string>, list<Endpoint>, list<NameIdFormat>, string}>
     */
    public static function provideListsOverTheirBound(): iterable
    {
        $certificate = MetadataFixtures::certificate('idp');
        yield 'seventeen signing certificates' => [
            array_fill(0, 17, $certificate),
            [],
            [],
            [],
            'A role holds more than 16 signing certificates, the bound of section 7 (M-17).',
        ];
        yield 'seventeen encryption certificates' => [
            [],
            array_fill(0, 17, $certificate),
            [],
            [],
            'A role holds more than 16 encryption certificates, the bound of section 7 (M-17).',
        ];
        yield 'sixty-five single logout services' => [
            [],
            [],
            array_fill(0, 65, new Endpoint(Binding::HttpRedirect, 'https://idp.example.com/slo')),
            [],
            'A role holds more than 64 single logout services, the bound of section 7 (M-17).',
        ];
        yield 'seventeen NameID formats' => [
            [],
            [],
            [],
            array_fill(0, 17, NameIdFormat::Transient),
            'A role holds more than 16 NameID formats, the bound of section 7 (M-17).',
        ];
    }

    /**
     * M-6: the entity ID is an absolute URI.
     */
    #[Test]
    public function itRefusesARelativeEntityId(): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A URI is not absolute (M-6).');

        // When
        RoleRules::check('idp', [], [], [], []);
    }

    /**
     * D-16, section 6.5 step 5: a certificate, signing or encryption, is checked by building its Dsig key.
     *
     * @param list<string> $signing
     * @param list<string> $encryption
     */
    #[Test]
    #[DataProvider('provideCertificatesRefused')]
    public function itRefusesACertificateDsigRefuses(array $signing, array $encryption, string $message): void
    {
        // Then
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessageIs($message);

        // When
        RoleRules::check('https://idp.example.com', $signing, $encryption, [], []);
    }

    /**
     * @return iterable<string, array{list<string>, list<string>, string}>
     */
    public static function provideCertificatesRefused(): iterable
    {
        yield 'a signing certificate of an RSA key of 1024 bits' => [
            [MetadataFixtures::certificate('idp'), MetadataFixtures::certificate('rsa-1024')],
            [],
            'A verification key is RSA of at least 2048 bits (D-16).',
        ];
        yield 'an encryption certificate that is not base64' => [
            [],
            [MetadataFixtures::certificate('sp'), 'not base64'],
            'A certificate is the base64 of its DER (D-16).',
        ];
    }

    /**
     * M-3, section 5.3: no signing certificate, no keys.
     */
    #[Test]
    public function itHasNoKeysWithoutASigningCertificate(): void
    {
        // When / Then
        static::assertNull(RoleRules::verificationKeys([]));
    }

    /**
     * M-3: one key per signing certificate.
     */
    #[Test]
    public function itHasOneKeyPerSigningCertificate(): void
    {
        // When
        $keys = RoleRules::verificationKeys([
            MetadataFixtures::certificate('idp'),
            MetadataFixtures::certificate('sp'),
        ]);

        // Then
        static::assertCount(2, $keys->keys ?? []);
    }
}
