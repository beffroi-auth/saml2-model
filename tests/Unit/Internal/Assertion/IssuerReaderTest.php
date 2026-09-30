<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion;

use Beffroi\Saml2\Model\Exception\IssuerMismatch;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Assertion\IssuerReader;
use Beffroi\Saml2\Model\SamlLoader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * M-8, section 6.1 step 7: the Issuer of an assertion, the identity provider's entity ID, its Format omitted or entity
 * (SAML Profiles §4.1.4.2, SAML Core §2.2.5); M-1, section 5.4: the Issuer of a message as it arrived, which chooses
 * the peer.
 */
final class IssuerReaderTest extends TestCase
{
    use AssertionFixtures;

    /**
     * M-8, SAML Core §2.2.5: without Format, or with the entity format, the Issuer is the peer's entity ID, as read.
     */
    #[Test]
    #[DataProvider('provideIssuers')]
    public function itReadsTheEntityIdOfThePeer(string $fixture): void
    {
        // Given
        $issuer = $this->child($this->document($fixture), 'Issuer');

        // When
        $read = IssuerReader::read($issuer, 'https://idp.example.com/saml');

        // Then
        static::assertSame('https://idp.example.com/saml', $read->entityId);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideIssuers(): iterable
    {
        yield 'Format omitted' => ['behaviour/assertion-valid-accepted.xml'];
        yield 'Format entity' => ['behaviour/assertion-issuer-format-entity-accepted.xml'];
    }

    /**
     * §9.2 row 16, M-8: the assertion's Issuer another entity, or with a Format other than entity.
     */
    #[Test]
    #[DataProvider('provideMismatchedIssuers')]
    public function itRefusesAnIssuerThatIsNotThePeers(string $fixture, string $message): void
    {
        // Given
        $document = $this->document($fixture);

        // Then
        $this->expectException(IssuerMismatch::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        IssuerReader::read($this->child($document, 'Issuer'), 'https://idp.example.com/saml');
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMismatchedIssuers(): iterable
    {
        yield 'another entity' => [
            'hostile/assertion-issuer-another-entity-refused.xml',
            'The Issuer is not the entity ID of the peer (M-8).',
        ];
        yield 'Format unspecified' => [
            'hostile/assertion-issuer-format-unspecified-refused.xml',
            'The Issuer has a Format other than entity (M-8).',
        ];
    }

    /**
     * M-8, SAML Core §8.3.6: an entity identifier omits NameQualifier, SPNameQualifier and SPProvidedID, and an Issuer
     * carrying one is not the peer's entity ID.
     */
    #[Test]
    #[DataProvider('provideQualifiedIssuers')]
    public function itRefusesAnIssuerCarryingAQualifier(string $fixture): void
    {
        // Given
        $document = $this->document($fixture);
        $message = 'The Issuer carries a NameQualifier, an SPNameQualifier or an SPProvidedID, which an entity identifier omits (M-8).';

        // Then
        $this->expectException(IssuerMismatch::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        IssuerReader::read($this->child($document, 'Issuer'), 'https://idp.example.com/saml');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideQualifiedIssuers(): iterable
    {
        yield 'NameQualifier' => ['hostile/assertion-issuer-name-qualifier-refused.xml'];
        yield 'SPNameQualifier' => ['hostile/assertion-issuer-sp-name-qualifier-refused.xml'];
        yield 'SPProvidedID' => ['hostile/assertion-issuer-sp-provided-id-refused.xml'];
    }

    /**
     * Section 5.4, M-1: the Issuer of a message as it arrived, a URI of M-6, or null when it has none.
     */
    #[Test]
    #[DataProvider('provideUnverifiedIssuers')]
    public function itReadsTheIssuerThatChoosesThePeer(string $xml, ?string $expected): void
    {
        // Given
        $parent = SamlLoader::create()->load($xml)->root();

        // When
        $issuer = IssuerReader::unverified($parent, 'samlp:LogoutRequest');

        // Then
        static::assertSame($expected, $issuer);
    }

    /**
     * @return iterable<string, array{string, ?string}>
     */
    public static function provideUnverifiedIssuers(): iterable
    {
        yield 'one' => [
            '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>https://idp.example.com/saml</saml:Issuer></samlp:LogoutRequest>',
            'https://idp.example.com/saml',
        ];
        yield 'none' => ['<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>', null];
    }

    /**
     * M-4, section 5.4: two Issuers leave the consumer two peers to choose from, and neither is picked.
     */
    #[Test]
    public function itRefusesTwoIssuersBeforeAnyVerification(): void
    {
        // Given
        $parent = SamlLoader::create()
            ->load('<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>https://idp.example.com/saml</saml:Issuer><saml:Issuer>https://idp.example.com/saml</saml:Issuer></samlp:LogoutRequest>')
            ->root();

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The samlp:LogoutRequest holds more than one saml:Issuer (M-4).');

        // When
        IssuerReader::unverified($parent, 'samlp:LogoutRequest');
    }
}
