<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Value;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Boolean;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * M-6: a boolean is one of its four lexical forms, compared as a string and never cast (XML Schema Part 2 §3.2.2.1).
 */
final class BooleanTest extends TestCase
{
    /**
     * XML Schema Part 2 §3.2.2.1: true and 1, false and 0.
     */
    #[Test]
    #[DataProvider('provideBooleans')]
    public function itReadsTheFourLexicalForms(string $value, bool $expected): void
    {
        // When / Then
        static::assertSame($expected, Boolean::read($value));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideBooleans(): iterable
    {
        yield 'true' => ['true', true];
        yield '1' => ['1', true];
        yield 'false' => ['false', false];
        yield '0' => ['0', false];
    }

    /**
     * §9.2 row 26, M-6: any other string, compared byte for byte; the message carries nothing of it (M-16).
     */
    #[Test]
    #[DataProvider('provideNotABoolean')]
    public function itRefusesEveryOtherString(string $value): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A boolean is not one of true, false, 1 and 0 (M-6).');

        // When
        Boolean::read($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNotABoolean(): iterable
    {
        yield 'TRUE' => ['TRUE'];
        yield 'True' => ['True'];
        yield 'FALSE' => ['FALSE'];
        yield 'a leading space' => [' true'];
        yield 'a trailing space' => ['true '];
        yield 'a trailing newline' => ["false\n"];
        yield 'yes' => ['yes'];
        yield 'no' => ['no'];
        yield 'on' => ['on'];
        yield '01' => ['01'];
        yield '1.0' => ['1.0'];
        yield '-0' => ['-0'];
        yield 'empty' => [''];
    }

    /**
     * M-15: the package writes true and false, never 1 and 0.
     */
    #[Test]
    #[DataProvider('provideWrittenBooleans')]
    public function itWritesTrueAndFalse(string $written, string $expected): void
    {
        // When / Then
        static::assertSame($expected, $written);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideWrittenBooleans(): iterable
    {
        yield 'true' => [Boolean::TRUE, 'true'];
        yield 'false' => [Boolean::FALSE, 'false'];
    }
}
