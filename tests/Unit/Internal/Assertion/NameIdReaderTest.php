<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion;

use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\InvalidNameId;
use Beffroi\Saml2\Model\Internal\Assertion\NameIdReader;
use Beffroi\Saml2\Model\SamlLoader;
use Dom\Element;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * M-12, SAML Core §2.2.3: the one reader of a saml:NameID, the subject of an assertion and the principal of a logout
 * request.
 */
final class NameIdReaderTest extends TestCase
{
    /**
     * M-12, SAML Core §8.3.7: the value as read, the format, and the three qualifiers.
     */
    #[Test]
    public function itReadsTheValueTheFormatAndTheQualifiers(): void
    {
        // Given
        $nameId = $this->nameId('<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" NameQualifier="https://idp.example.com/saml" SPNameQualifier="https://sp.example.com/saml" SPProvidedID="sp-7">_7a2f4c1d9e</saml:NameID>');

        // When
        $read = NameIdReader::read($nameId);

        // Then
        static::assertSame(
            [
                '_7a2f4c1d9e',
                NameIdFormat::Persistent,
                'https://idp.example.com/saml',
                'https://sp.example.com/saml',
                'sp-7',
            ],
            [$read->value, $read->format, $read->nameQualifier, $read->spNameQualifier, $read->spProvidedId],
        );
    }

    /**
     * §9.3 row 1, M-12, I-12: a value split by a comment is read whole, the comment dropped, absent Format meaning
     * unspecified.
     */
    #[Test]
    public function itReadsAValueSplitByACommentWhole(): void
    {
        // Given
        $nameId = $this->nameId('<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">user@example.com<!---->.evil.com</saml:NameID>');

        // When
        $read = NameIdReader::read($nameId);

        // Then
        static::assertSame(['user@example.com.evil.com', NameIdFormat::Unspecified], [$read->value, $read->format]);
    }

    /**
     * M-12, SAML Core §8.3: a Format SAML Core does not list is refused.
     */
    #[Test]
    public function itRefusesAnUnknownFormat(): void
    {
        // Given
        $nameId = $this->nameId('<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:example:format">_7a2f4c1d9e</saml:NameID>');

        // Then
        $this->expectException(InvalidNameId::class);
        $this->expectExceptionMessageIs('The NameID format is not one of the eight of SAML Core (M-12).');

        // When
        NameIdReader::read($nameId);
    }

    private function nameId(string $xml): Element
    {
        return SamlLoader::create()->load($xml)->root();
    }
}
