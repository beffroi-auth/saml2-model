<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Value;

use Beffroi\Saml2\Model\Value\Characters;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * M-6, M-12, M-15: the two rules of the characters a value may hold, what XML 1.0 carries (XML 1.0 §2.2) and what is
 * visible.
 */
final class CharactersTest extends TestCase
{
    /**
     * M-15: a value whose every character is one of XML 1.0's Char, at each edge of its ranges.
     */
    #[Test]
    #[DataProvider('provideCarried')]
    public function itTellsTheCharactersXmlCarries(string $value): void
    {
        // When / Then
        static::assertTrue(Characters::carriedByXml($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCarried(): iterable
    {
        yield 'nothing' => [''];
        yield 'ASCII' => ['jdoe@example.com'];
        yield 'a tab' => ["a\tb"];
        yield 'a line feed' => ["a\nb"];
        yield 'a carriage return' => ["a\rb"];
        yield 'a space' => ['a b'];
        yield 'U+D7FF' => ["a\u{D7FF}b"];
        yield 'U+E000' => ["a\u{E000}b"];
        yield 'U+FFFD' => ["a\u{FFFD}b"];
        yield 'U+10000' => ["a\u{10000}b"];
        yield 'U+10FFFF' => ["a\u{10FFFF}b"];
    }

    /**
     * M-15: a NUL, which the DOM truncates the value at, and every other character XML 1.0 does not carry, which the
     * reload of the Signer refuses; bytes that are not UTF-8.
     */
    #[Test]
    #[DataProvider('provideNotCarried')]
    public function itTellsTheCharactersXmlDoesNotCarry(string $value): void
    {
        // When / Then
        static::assertFalse(Characters::carriedByXml($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNotCarried(): iterable
    {
        yield 'a NUL inside' => ["admin\u{0}.attacker"];
        yield 'a NUL at the start' => ["\u{0}admin"];
        yield 'a NUL at the end' => ["admin\u{0}"];
        yield 'U+0008' => ["a\u{8}b"];
        yield 'U+000B' => ["a\u{B}b"];
        yield 'U+000C' => ["a\u{C}b"];
        yield 'U+001F' => ["a\u{1F}b"];
        yield 'U+FFFE' => ["a\u{FFFE}b"];
        yield 'U+FFFF' => ["a\u{FFFF}b"];
        yield 'bytes that are not UTF-8' => ["a\xFFb"];
    }

    /**
     * M-6, M-12: a value without an invisible character, the neighbours of each range included.
     */
    #[Test]
    #[DataProvider('provideVisible')]
    public function itTellsAVisibleValue(string $value): void
    {
        // When / Then
        static::assertTrue(Characters::visible($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideVisible(): iterable
    {
        yield 'nothing' => [''];
        yield 'ASCII with a space' => ['John Doe'];
        yield 'a two-byte letter' => ["\u{101}"];
        yield 'U+034E' => ["a\u{34E}b"];
        yield 'U+0350' => ["a\u{350}b"];
        yield 'U+115E' => ["a\u{115E}b"];
        yield 'U+1161' => ["a\u{1161}b"];
        yield 'U+17B3' => ["a\u{17B3}b"];
        yield 'U+17B6' => ["a\u{17B6}b"];
        yield 'U+180A' => ["a\u{180A}b"];
        yield 'U+1810' => ["a\u{1810}b"];
        yield 'U+27FF' => ["a\u{27FF}b"];
        yield 'U+2801' => ["a\u{2801}b"];
        yield 'U+3163' => ["a\u{3163}b"];
        yield 'U+3165' => ["a\u{3165}b"];
        yield 'U+FE10' => ["a\u{FE10}b"];
        yield 'U+FF9F' => ["a\u{FF9F}b"];
        yield 'U+FFA1' => ["a\u{FFA1}b"];
        yield 'U+FFEF' => ["a\u{FFEF}b"];
        yield 'U+FFFC' => ["a\u{FFFC}b"];
        yield 'U+DFFFF' => ["a\u{DFFFF}b"];
        yield 'U+E1000' => ["a\u{E1000}b"];
    }

    /**
     * M-6, M-12: a format character, a default-ignorable code point of another category or a blank filler, each one
     * rendered as nothing, and bytes that are not UTF-8.
     */
    #[Test]
    #[DataProvider('provideInvisible')]
    public function itTellsAnInvisibleCharacter(string $value): void
    {
        // When / Then
        static::assertFalse(Characters::visible($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvisible(): iterable
    {
        yield 'U+00AD' => ["a\u{AD}b"];
        yield 'U+200B' => ["a\u{200B}b"];
        yield 'U+202E' => ["a\u{202E}b"];
        yield 'U+FEFF' => ["a\u{FEFF}b"];
        yield 'U+034F' => ["a\u{34F}b"];
        yield 'U+115F' => ["a\u{115F}b"];
        yield 'U+1160' => ["a\u{1160}b"];
        yield 'U+17B4' => ["a\u{17B4}b"];
        yield 'U+17B5' => ["a\u{17B5}b"];
        yield 'U+180B' => ["a\u{180B}b"];
        yield 'U+180F' => ["a\u{180F}b"];
        yield 'U+2064' => ["a\u{2064}b"];
        yield 'U+2065' => ["a\u{2065}b"];
        yield 'U+2800' => ["a\u{2800}b"];
        yield 'U+3164' => ["a\u{3164}b"];
        yield 'U+FE00' => ["a\u{FE00}b"];
        yield 'U+FE0F' => ["a\u{FE0F}b"];
        yield 'U+FFA0' => ["a\u{FFA0}b"];
        yield 'U+FFF0' => ["a\u{FFF0}b"];
        yield 'U+FFF8' => ["a\u{FFF8}b"];
        yield 'U+E0000' => ["a\u{E0000}b"];
        yield 'U+E0001' => ["a\u{E0001}b"];
        yield 'U+E0100' => ["a\u{E0100}b"];
        yield 'U+E0FFF' => ["a\u{E0FFF}b"];
        yield 'bytes that are not UTF-8' => ["a\xFFb"];
    }
}
