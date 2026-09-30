<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Assertion;

use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\InvalidNameId;
use function array_map;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3, M-12: the name identifier formats, a closed vocabulary (SAML Core §8.3).
 */
final class NameIdFormatTest extends TestCase
{
    /**
     * SAML Core §8.3.1 to §8.3.8, E60: the eight URIs, the unspecified one under 1.1.
     */
    #[Test]
    public function itHoldsTheEightFormatsOfSamlCore(): void
    {
        // When
        $uris = array_map(static fn (NameIdFormat $format): string => $format->value, NameIdFormat::cases());

        // Then
        static::assertSame(
            [
                'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
                'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
                'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName',
                'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName',
                'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos',
                'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
                'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
                'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
            ],
            $uris,
        );
    }

    #[Test]
    #[DataProvider('provideFormats')]
    public function itReadsEachFormatFromItsUri(NameIdFormat $format): void
    {
        // When / Then
        static::assertSame($format, NameIdFormat::fromUri($format->value));
    }

    /**
     * @return iterable<string, array{NameIdFormat}>
     */
    public static function provideFormats(): iterable
    {
        foreach (NameIdFormat::cases() as $format) {
            yield $format->name => [$format];
        }
    }

    /**
     * M-12, SAML Core §2.2.2 as corrected by E60: a NameID without Format is of the unspecified format.
     */
    #[Test]
    public function itReadsAnAbsentFormatAsUnspecified(): void
    {
        // When / Then
        static::assertSame(NameIdFormat::Unspecified, NameIdFormat::fromUri(null));
    }

    /**
     * §9.2 row 27, M-12: an unknown Format, compared byte for byte; the message carries nothing of it (M-16).
     */
    #[Test]
    #[DataProvider('provideUnknownFormats')]
    public function itRefusesAnUnknownFormat(string $uri): void
    {
        // Then
        $this->expectException(InvalidNameId::class);
        $this->expectExceptionMessageIs('The NameID format is not one of the eight of SAML Core (M-12).');

        // When
        NameIdFormat::fromUri($uri);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUnknownFormats(): iterable
    {
        yield 'a format of its own' => ['urn:example:nameid-format:employee'];
        yield 'the 1.0 unspecified URI that E60 corrects' => ['urn:oasis:names:tc:SAML:1.0:nameid-format:unspecified'];
        yield 'unspecified under 2.0' => ['urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified'];
        yield 'the encrypted format of a NameIDPolicy' => ['urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted'];
        yield 'a case that differs' => ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailaddress'];
        yield 'a leading space' => [' urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'];
        yield 'a trailing newline' => ["urn:oasis:names:tc:SAML:2.0:nameid-format:transient\n"];
        yield 'empty' => [''];
    }
}
