<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion;

use Beffroi\Saml2\Model\Exception\IssuerMismatch;
use Beffroi\Saml2\Model\Internal\Assertion\IssuerReader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * M-8, section 6.1 step 7: the Issuer of an assertion, the identity provider's entity ID, its Format omitted or entity
 * (SAML Profiles §4.1.4.2, SAML Core §2.2.5).
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
}
