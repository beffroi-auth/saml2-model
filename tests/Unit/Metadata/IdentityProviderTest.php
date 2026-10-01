<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Metadata;

use function array_fill;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\Verifier;
use Beffroi\Saml2\Model\SamlLoader;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3: the identity provider role of an entity, under the rules of its values and the counts of section 7
 * (SAML Metadata §2.4.3).
 */
final class IdentityProviderTest extends TestCase
{
    /**
     * Section 5.3: every field, kept as given.
     */
    #[Test]
    public function itKeepsItsFields(): void
    {
        // Given
        $singleSignOn = [new Endpoint(Binding::HttpRedirect, 'https://idp.example.com/sso')];
        $singleLogout = [new Endpoint(Binding::HttpPost, 'https://idp.example.com/slo')];

        // When
        $idp = new IdentityProvider(
            'https://idp.example.com',
            [MetadataFixtures::certificate('idp')],
            [MetadataFixtures::certificate('sp')],
            $singleSignOn,
            $singleLogout,
            [NameIdFormat::Persistent, NameIdFormat::Transient],
            true,
        );

        // Then
        static::assertSame(
            [
                'https://idp.example.com',
                [MetadataFixtures::certificate('idp')],
                [MetadataFixtures::certificate('sp')],
                $singleSignOn,
                $singleLogout,
                [NameIdFormat::Persistent, NameIdFormat::Transient],
                true,
            ],
            [
                $idp->entityId,
                $idp->signingCertificates,
                $idp->encryptionCertificates,
                $idp->singleSignOnServices,
                $idp->singleLogoutServices,
                $idp->nameIdFormats,
                $idp->wantAuthnRequestsSigned,
            ],
        );
    }

    /**
     * Section 6.5 step 7: no single logout service, no format, and the requests not wanted signed, by default.
     */
    #[Test]
    public function itHasNoLogoutServiceNoFormatAndWantsNoSignedRequestByDefault(): void
    {
        // When
        $idp = new IdentityProvider('https://idp.example.com', [], [], [$this->singleSignOn()]);

        // Then
        static::assertSame([[], [], false], [
            $idp->singleLogoutServices,
            $idp->nameIdFormats,
            $idp->wantAuthnRequestsSigned,
        ]);
    }

    /**
     * Section 7: 64 single sign-on services, the bound itself.
     */
    #[Test]
    public function itAcceptsSixtyFourSingleSignOnServices(): void
    {
        // When
        $idp = new IdentityProvider('https://idp.example.com', [], [], array_fill(0, 64, $this->singleSignOn()));

        // Then
        static::assertCount(64, $idp->singleSignOnServices);
    }

    /**
     * M-17, section 9.2 row "one over each bound of section 7": 65 single sign-on services.
     */
    #[Test]
    public function itRefusesSixtyFiveSingleSignOnServices(): void
    {
        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('A role holds more than 64 single sign-on services, the bound of section 7 (M-17).');

        // When
        new IdentityProvider('https://idp.example.com', [], [], array_fill(0, 65, $this->singleSignOn()));
    }

    /**
     * M-17: the rules the two roles share apply, here seventeen signing certificates.
     */
    #[Test]
    public function itAppliesTheRulesOfARole(): void
    {
        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('A role holds more than 16 signing certificates, the bound of section 7 (M-17).');

        // When
        new IdentityProvider(
            'https://idp.example.com',
            array_fill(0, 17, MetadataFixtures::certificate('idp')),
            [],
            [$this->singleSignOn()],
        );
    }

    /**
     * M-3, section 5.3: the keys of its signing certificates, in their order, which verify what it signs.
     */
    #[Test]
    public function itHasTheKeysOfItsSigningCertificates(): void
    {
        // Given
        $idp = new IdentityProvider(
            'https://idp.example.com',
            [MetadataFixtures::certificate('sp'), MetadataFixtures::certificate('idp')],
            [],
            [$this->singleSignOn()],
        );
        $signature = MetadataFixtures::signingKey('idp')->sign('signed bytes', SignatureAlgorithm::RsaSha256);

        // When
        $keys = $idp->verificationKeys() ?? static::fail('The role has signing certificates.');

        // Then
        static::assertCount(2, $keys->keys);
        static::assertSame(
            $keys->keys[1],
            new Verifier(SamlLoader::create())->verifyDetached(
                'signed bytes',
                $signature,
                SignatureAlgorithm::RsaSha256,
                $keys,
            ),
        );
    }

    /**
     * Section 5.3, M-3: a role without a signing certificate has no keys, null rather than an empty list, which Dsig
     * refuses as a programming error.
     */
    #[Test]
    public function itHasNoKeysWithoutASigningCertificate(): void
    {
        // Given
        $idp = new IdentityProvider(
            'https://idp.example.com',
            [],
            [MetadataFixtures::certificate('idp')],
            [$this->singleSignOn()],
        );

        // When / Then
        static::assertNull($idp->verificationKeys());
    }

    private function singleSignOn(): Endpoint
    {
        return new Endpoint(Binding::HttpRedirect, 'https://idp.example.com/sso');
    }
}
