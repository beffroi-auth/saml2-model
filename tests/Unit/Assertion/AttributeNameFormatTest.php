<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Assertion;

use Beffroi\Saml2\Model\Assertion\AttributeNameFormat;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use function array_map;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3, M-5: the attribute name formats, a closed vocabulary (SAML Core §8.2).
 */
final class AttributeNameFormatTest extends TestCase
{
    /**
     * SAML Core §8.2.1 to §8.2.3: the three URIs.
     */
    #[Test]
    public function itHoldsTheThreeFormatsOfSamlCore(): void
    {
        // When
        $uris = array_map(
            static fn (AttributeNameFormat $format): string => $format->value,
            AttributeNameFormat::cases(),
        );

        // Then
        static::assertSame(
            [
                'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified',
                'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
                'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
            ],
            $uris,
        );
    }

    #[Test]
    #[DataProvider('provideFormats')]
    public function itReadsEachFormatFromItsUri(AttributeNameFormat $format): void
    {
        // When / Then
        static::assertSame($format, AttributeNameFormat::fromUri($format->value));
    }

    /**
     * @return iterable<string, array{AttributeNameFormat}>
     */
    public static function provideFormats(): iterable
    {
        foreach (AttributeNameFormat::cases() as $format) {
            yield $format->name => [$format];
        }
    }

    /**
     * SAML Core §2.7.3.1: an attribute without NameFormat is of the unspecified format.
     */
    #[Test]
    public function itReadsAnAbsentFormatAsUnspecified(): void
    {
        // When / Then
        static::assertSame(AttributeNameFormat::Unspecified, AttributeNameFormat::fromUri(null));
    }

    /**
     * M-5: an unknown NameFormat, compared byte for byte; the message carries nothing of it (M-16).
     */
    #[Test]
    #[DataProvider('provideUnknownFormats')]
    public function itRefusesAnUnknownFormat(string $uri): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The NameFormat of an attribute is not one of the three of SAML Core (M-5).');

        // When
        AttributeNameFormat::fromUri($uri);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUnknownFormats(): iterable
    {
        yield 'a format of its own' => ['urn:example:attrname-format:ldap'];
        yield 'the uri format under 1.1' => ['urn:oasis:names:tc:SAML:1.1:attrname-format:uri'];
        yield 'a case that differs' => ['urn:oasis:names:tc:SAML:2.0:attrname-format:URI'];
        yield 'a trailing space' => ['urn:oasis:names:tc:SAML:2.0:attrname-format:basic '];
        yield 'empty' => [''];
    }
}
