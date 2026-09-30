<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Writing;

use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.7: how a writer signs, the Dsig signing port, the algorithm and the KeyInfo hint of D-17.
 */
final class SigningTest extends TestCase
{
    /**
     * Section 5.7: the key, the algorithm and the certificate, kept as given.
     */
    #[Test]
    public function itKeepsItsFields(): void
    {
        // Given
        $key = MetadataFixtures::signingKey('idp');

        // When
        $signing = new Signing($key, SignatureAlgorithm::RsaSha512, MetadataFixtures::certificatePem('idp'));

        // Then
        static::assertSame(
            [$key, SignatureAlgorithm::RsaSha512, MetadataFixtures::certificatePem('idp')],
            [$signing->key, $signing->algorithm, $signing->certificatePem],
        );
    }

    /**
     * Section 5.7: RSA with SHA-256 and no KeyInfo, by default.
     */
    #[Test]
    public function itSignsWithRsaSha256AndNoKeyInfoByDefault(): void
    {
        // When
        $signing = new Signing(MetadataFixtures::signingKey('idp'));

        // Then
        static::assertSame([SignatureAlgorithm::RsaSha256, null], [$signing->algorithm, $signing->certificatePem]);
    }
}
