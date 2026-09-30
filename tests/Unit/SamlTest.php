<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit;

use Beffroi\Saml2\Model\Saml;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.1: the names of SAML 2.0 the package reads and writes.
 */
final class SamlTest extends TestCase
{
    /**
     * SAML Core §2 and §3, Metadata §2: the three namespaces, compared byte for byte wherever an element is matched;
     * M-6: the one version a message carries (SAML Core §2.3.3, §3.2.1).
     */
    #[Test]
    #[DataProvider('provideNames')]
    public function itHoldsTheNamesOfSaml(string $name, string $expected): void
    {
        // When / Then
        static::assertSame($expected, $name);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideNames(): iterable
    {
        yield 'the assertion namespace' => [Saml::ASSERTION, 'urn:oasis:names:tc:SAML:2.0:assertion'];
        yield 'the protocol namespace' => [Saml::PROTOCOL, 'urn:oasis:names:tc:SAML:2.0:protocol'];
        yield 'the metadata namespace' => [Saml::METADATA, 'urn:oasis:names:tc:SAML:2.0:metadata'];
        yield 'the version' => [Saml::VERSION, '2.0'];
    }
}
