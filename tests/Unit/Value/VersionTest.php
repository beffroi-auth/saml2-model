<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Value;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\Value\Version;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * M-6: the Version of a message or an assertion is 2.0 (SAML Core §2.3.3, §3.2.1).
 */
final class VersionTest extends TestCase
{
    /**
     * M-6, M-15: the version the package writes is the one it reads.
     */
    #[Test]
    public function itReadsTheVersionThePackageWrites(): void
    {
        // When / Then
        static::assertSame(Saml::VERSION, Version::read(Saml::VERSION));
    }

    /**
     * §9.2 row 26, M-6: any other string, compared byte for byte; the message carries nothing of it (M-16).
     */
    #[Test]
    #[DataProvider('provideOtherVersions')]
    public function itRefusesEveryOtherVersion(string $value): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The version is not 2.0 (M-6).');

        // When
        Version::read($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideOtherVersions(): iterable
    {
        yield '2.1' => ['2.1'];
        yield '1.1' => ['1.1'];
        yield '2' => ['2'];
        yield '2.00' => ['2.00'];
        yield '2,0' => ['2,0'];
        yield 'a leading space' => [' 2.0'];
        yield 'a trailing space' => ['2.0 '];
        yield 'empty' => [''];
    }
}
