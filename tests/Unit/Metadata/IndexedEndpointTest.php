<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Metadata;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3: an indexed endpoint, its location a URI of M-6 and its index an xs:unsignedShort (SAML Metadata
 * §2.2.3).
 */
final class IndexedEndpointTest extends TestCase
{
    /**
     * Section 5.3: the binding, the location, the index and isDefault, kept as given.
     */
    #[Test]
    public function itKeepsItsFields(): void
    {
        // When
        $endpoint = new IndexedEndpoint(Binding::HttpPost, 'https://sp.example.com/acs', 3, false);

        // Then
        static::assertSame(
            [Binding::HttpPost, 'https://sp.example.com/acs', 3, false],
            [$endpoint->binding, $endpoint->location, $endpoint->index, $endpoint->isDefault],
        );
    }

    /**
     * SAML Metadata §2.2.3: isDefault absent is null, which default() tells apart from false.
     */
    #[Test]
    public function itHasNoIsDefaultByDefault(): void
    {
        // When
        $endpoint = new IndexedEndpoint(Binding::HttpPost, 'https://sp.example.com/acs', 0);

        // Then
        static::assertNull($endpoint->isDefault);
    }

    /**
     * M-6: the two ends of xs:unsignedShort.
     */
    #[Test]
    #[DataProvider('provideIndexes')]
    public function itAcceptsAnUnsignedShort(int $index): void
    {
        // When
        $endpoint = new IndexedEndpoint(Binding::HttpPost, 'https://sp.example.com/acs', $index);

        // Then
        static::assertSame($index, $endpoint->index);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideIndexes(): iterable
    {
        yield 'zero' => [0];
        yield '65535' => [65_535];
    }

    /**
     * M-6: an index outside xs:unsignedShort.
     */
    #[Test]
    #[DataProvider('provideIndexesOutside')]
    public function itRefusesAnIndexOutsideAnUnsignedShort(int $index): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('An index is not an xs:unsignedShort, from 0 to 65535 (M-6).');

        // When
        new IndexedEndpoint(Binding::HttpPost, 'https://sp.example.com/acs', $index);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideIndexesOutside(): iterable
    {
        yield 'minus one' => [-1];
        yield '65536' => [65_536];
    }

    /**
     * M-6, section 6.5 step 6: the location is an absolute URI.
     */
    #[Test]
    public function itRefusesARelativeLocation(): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A URI is not absolute (M-6).');

        // When
        new IndexedEndpoint(Binding::HttpPost, 'acs', 0);
    }
}
