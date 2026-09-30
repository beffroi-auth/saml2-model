<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Value;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\UnsignedShort;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * M-6: an index is an xs:unsignedShort, from 0 to 65535, read in its one lexical form (XML Schema Part 2 §3.3.23),
 * the index of an md:AssertionConsumerService (SAML Metadata §2.2.3) and the AssertionConsumerServiceIndex of an
 * AuthnRequest (SAML Core §3.4.1).
 */
final class UnsignedShortTest extends TestCase
{
    /**
     * M-6: decimal digits without sign or leading zero, both ends included.
     */
    #[Test]
    #[DataProvider('provideIndexes')]
    public function itReadsAnIndex(string $value, int $expected): void
    {
        // When / Then
        static::assertSame($expected, UnsignedShort::read($value));
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideIndexes(): iterable
    {
        yield '0' => ['0', 0];
        yield '1' => ['1', 1];
        yield '65535' => ['65535', 65_535];
    }

    /**
     * §9.2 row 26, M-6: every other form, the value over 65535 included; the message carries nothing of it (M-16).
     */
    #[Test]
    #[DataProvider('provideNotAnIndex')]
    public function itRefusesEveryOtherForm(string $value): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('An index is not an xs:unsignedShort, digits without sign or leading zero from 0 to 65535 (M-6).');

        // When
        UnsignedShort::read($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNotAnIndex(): iterable
    {
        yield 'empty' => [''];
        yield 'a sign' => ['+1'];
        yield 'negative' => ['-1'];
        yield 'a leading zero' => ['01'];
        yield 'surrounding whitespace' => [' 1'];
        yield 'a trailing line feed' => ["1\n"];
        yield 'a decimal point' => ['1.0'];
        yield 'one over the bound' => ['65536'];
        yield 'six digits' => ['100000'];
    }

    /**
     * M-6, M-15: an index built as an integer holds whoever builds it, both ends included.
     */
    #[Test]
    #[DataProvider('provideIntegers')]
    public function itChecksAnIntegerIndex(int $value): void
    {
        // When / Then
        static::assertSame($value, UnsignedShort::check($value));
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideIntegers(): iterable
    {
        yield '0' => [0];
        yield '65535' => [65_535];
    }

    /**
     * M-6: an integer under 0 or over 65535 is not an index.
     */
    #[Test]
    #[DataProvider('provideIntegersOutOfRange')]
    public function itRefusesAnIntegerOutOfRange(int $value): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('An index is not an xs:unsignedShort, digits without sign or leading zero from 0 to 65535 (M-6).');

        // When
        UnsignedShort::check($value);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideIntegersOutOfRange(): iterable
    {
        yield '-1' => [-1];
        yield '65536' => [65_536];
    }
}
