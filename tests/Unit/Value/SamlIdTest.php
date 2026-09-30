<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Value;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Xml\Core\NcName;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * M-6, M-15: an ID and an InResponseTo are NCNames of at most 128 bytes; an ID the package writes holds 160 random bits
 * (SAML Core §1.3.4).
 */
final class SamlIdTest extends TestCase
{
    /**
     * §9.3 row 17, M-15, SAML Core §1.3.4: an underscore and the 40 lowercase hexadecimal digits of 160 bits, 41 bytes.
     */
    #[Test]
    public function itGeneratesAnUnderscoreAndFortyLowercaseHexadecimalDigits(): void
    {
        // When
        $id = SamlId::generate();

        // Then
        static::assertMatchesRegularExpression('~^_[0-9a-f]{40}\z~', $id);
    }

    /**
     * §9.3 row 17, core.md I-8: what the package generates, the loader indexes.
     */
    #[Test]
    public function itGeneratesAnNcName(): void
    {
        // When
        $id = SamlId::generate();

        // Then
        static::assertTrue(NcName::is($id));
    }

    /**
     * §9.3 row 17, SAML Core §1.3.4: negligible probability that two identifiers are the same.
     */
    #[Test]
    public function itGeneratesADifferentIdOnEachCall(): void
    {
        // When
        $first = SamlId::generate();
        $second = SamlId::generate();

        // Then
        static::assertNotSame($first, $second);
    }

    /**
     * M-6, core.md I-8: an NCName of at most 128 bytes, returned as it is.
     */
    #[Test]
    #[DataProvider('provideIds')]
    public function itReadsAnId(string $value): void
    {
        // When / Then
        static::assertSame($value, SamlId::read($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideIds(): iterable
    {
        yield 'one the package generates' => [SamlId::generate()];
        yield 'a GUID after an underscore' => ['_2cac9ed1-b223-4fb8-83bd-03d6f59d682d'];
        yield 'a letter alone' => ['a'];
        yield 'dots and hyphens after the first character' => ['id.a-b'];
        yield 'exactly 128 bytes' => ['_' . str_repeat('a', 127)];
        yield 'exactly 128 bytes of two-byte characters' => [str_repeat("\u{E9}", 64)];
    }

    /**
     * Section 7: longer than the maxIdLength of Core, counted in bytes; the message carries nothing of it (M-16).
     */
    #[Test]
    #[DataProvider('provideTooLong')]
    public function itRefusesAnIdLongerThan128Bytes(string $value): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('An ID is longer than 128 bytes (M-6).');

        // When
        SamlId::read($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTooLong(): iterable
    {
        yield '129 bytes' => ['_' . str_repeat('a', 128)];
        yield '65 two-byte characters, 130 bytes' => [str_repeat("\u{E9}", 65)];
    }

    /**
     * M-6, core.md I-8, Namespaces in XML 1.0 §3: an ID or an InResponseTo that is not an NCName.
     */
    #[Test]
    #[DataProvider('provideNotAnNcName')]
    public function itRefusesWhatIsNotAnNcName(string $value): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('An ID is not an NCName (M-6).');

        // When
        SamlId::read($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNotAnNcName(): iterable
    {
        yield 'empty' => [''];
        yield 'a leading digit' => ['1abc'];
        yield 'a colon' => ['_a:b'];
        yield 'a leading space' => [' _abc'];
        yield 'a trailing space' => ['_abc '];
        yield 'a trailing newline' => ["_abc\n"];
        yield 'a hash' => ['#_abc'];
    }
}
