<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Value;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Uri;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * M-6: a URI is absolute (SAML Core §1.3.2, RFC 3986 §4.3), holds no whitespace and no control character, and is at
 * most 1024 characters (SAML Core §8.3.6, section 7).
 */
final class UriTest extends TestCase
{
    /**
     * M-6, M-8: an absolute URI, returned as it is, never normalised.
     */
    #[Test]
    #[DataProvider('provideUris')]
    public function itReadsAnAbsoluteUri(string $value): void
    {
        // When / Then
        static::assertSame($value, Uri::read($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUris(): iterable
    {
        yield 'an https URL' => ['https://idp.example.com/saml/metadata'];
        yield 'a URN' => ['urn:oasis:names:tc:SAML:2.0:protocol'];
        yield 'a query and a fragment' => ['https://sp.example.com/acs?a=1&b=%20#top'];
        yield 'a trailing slash, kept' => ['https://sp.example.com/'];
        yield 'an uppercase scheme and host, kept' => ['HTTPS://SP.EXAMPLE.COM/acs'];
        yield 'a scheme with a plus, a point and a hyphen' => ['a+b.c-d:e'];
        yield 'a scheme alone' => ['urn:'];
        yield 'a colon later in the path' => ['https://example.com/a:b'];
        yield 'a two-byte character' => ["https://example.com/\u{101}"];
        yield 'exactly 1024 characters' => ['https://example.com/' . str_repeat('a', 1004)];
        yield 'exactly 1024 characters, two bytes each after the scheme' => ['urn:' . str_repeat("\u{E9}", 1020)];
    }

    /**
     * §9.2 row 26, section 7, SAML Core §8.3.6: longer than 1024 characters; the message carries nothing of it (M-16).
     */
    #[Test]
    #[DataProvider('provideTooLong')]
    public function itRefusesAUriLongerThan1024Characters(string $value): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A URI is longer than 1024 characters (M-6).');

        // When
        Uri::read($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTooLong(): iterable
    {
        yield 'an entity ID of 1025 characters' => ['https://example.com/' . str_repeat('a', 1005)];
        yield '1025 characters, two bytes each after the scheme' => ['urn:' . str_repeat("\u{E9}", 1021)];
    }

    /**
     * M-6, SAML Core §1.3.2: whitespace or a control character, anywhere, and bytes that are not UTF-8.
     */
    #[Test]
    #[DataProvider('provideWhitespaceOrControl')]
    public function itRefusesWhitespaceAndControlCharacters(string $value): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A URI holds whitespace, a control character or bytes that are not UTF-8 (M-6).');

        // When
        Uri::read($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhitespaceOrControl(): iterable
    {
        yield 'a leading space' => [' https://example.com/'];
        yield 'a trailing space' => ['https://example.com/ '];
        yield 'a space inside' => ['https://example.com/a b'];
        yield 'a tab' => ["https://example.com/a\tb"];
        yield 'a trailing newline' => ["https://example.com/\n"];
        yield 'a carriage return' => ["https://example.com/a\rb"];
        yield 'a delete' => ["https://example.com/\x7F"];
        yield 'a next line' => ["https://example.com/\u{85}"];
        yield 'a no-break space' => ["https://example.com/\u{A0}"];
        yield 'a line separator' => ["https://example.com/\u{2028}"];
        yield 'an ideographic space' => ["https://example.com/\u{3000}"];
        yield 'a byte that is not UTF-8' => ["https://example.com/\xFF"];
    }

    /**
     * §9.2 row 26, M-6, RFC 3986 §4.3: a relative reference, or a scheme that does not start with a letter.
     */
    #[Test]
    #[DataProvider('provideNotAbsolute')]
    public function itRefusesAUriThatIsNotAbsolute(string $value): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A URI is not absolute (M-6).');

        // When
        Uri::read($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNotAbsolute(): iterable
    {
        yield 'a relative path' => ['relative/path'];
        yield 'a colon after a slash' => ['relative/path:x'];
        yield 'an absolute path' => ['/acs'];
        yield 'a network-path reference' => ['//sp.example.com/acs'];
        yield 'a fragment alone' => ['#top'];
        yield 'a scheme starting with a digit' => ['1https://example.com/'];
        yield 'a scheme starting with a plus' => ['+a:b'];
        yield 'a scheme with an underscore' => ['a_b:c'];
        yield 'a scheme outside ASCII' => ["\u{E9}:x"];
        yield 'empty' => [''];
    }
}
