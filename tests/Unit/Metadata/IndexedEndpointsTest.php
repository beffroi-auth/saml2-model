<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Metadata;

use function array_map;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\UnknownEndpoint;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function range;

/**
 * Section 5.3, M-9: the assertion consumer services of a service provider, their indexes unique, and the three
 * searches that resolve the endpoint of a request (SAML Metadata §2.2.3).
 */
final class IndexedEndpointsTest extends TestCase
{
    /**
     * Section 5.3: the endpoints, in the order given.
     */
    #[Test]
    public function itKeepsItsEndpointsInOrder(): void
    {
        // Given
        $first = self::endpoint(2);
        $second = self::endpoint(1);

        // When
        $endpoints = new IndexedEndpoints([$first, $second]);

        // Then
        static::assertSame([$first, $second], $endpoints->endpoints);
    }

    /**
     * Section 7: 64 endpoints of one kind, the bound itself.
     */
    #[Test]
    public function itAcceptsSixtyFourEndpoints(): void
    {
        // When
        $endpoints = new IndexedEndpoints($this->endpoints(64));

        // Then
        static::assertCount(64, $endpoints->endpoints);
    }

    /**
     * M-17, §9.2 row 36, "one over each bound of section 7": 65 endpoints of one kind.
     */
    #[Test]
    public function itRefusesSixtyFiveEndpoints(): void
    {
        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('A role holds more than 64 assertion consumer services, the bound of section 7 (M-17).');

        // When
        new IndexedEndpoints($this->endpoints(65));
    }

    /**
     * §9.2 row 35, "a duplicate index", SAML Metadata §2.2.3: an index names one endpoint.
     */
    #[Test]
    public function itRefusesADuplicateIndex(): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('Two assertion consumer services share an index (section 6.5).');

        // When
        new IndexedEndpoints([self::endpoint(0), self::endpoint(1), self::endpoint(0)]);
    }

    /**
     * M-9, section 8: an assertion consumer service on another binding than HTTP-POST, which a response cannot be sent
     * over, is refused whoever builds the list, so that no search establishes it; the reader drops it before.
     */
    #[Test]
    public function itRefusesAnEndpointNotOnHttpPost(): void
    {
        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs('An assertion consumer service is not on HTTP-POST, the one binding the package answers over (section 8).');

        // When
        new IndexedEndpoints([
            self::endpoint(0),
            new IndexedEndpoint(Binding::HttpRedirect, 'https://sp.example.com/acs/redirect', 1),
        ]);
    }

    /**
     * §9.3 row 12, "IndexedEndpoints::default() over the three cases", SAML Metadata §2.2.3: the first whose
     * isDefault is true; else the first without isDefault false; else the first.
     *
     * @param list<?bool> $isDefaults
     */
    #[Test]
    #[DataProvider('provideDefaults')]
    public function itResolvesTheDefaultEndpoint(array $isDefaults, int $expected): void
    {
        // Given
        $endpoints = new IndexedEndpoints(array_map(
            static fn (int $index): IndexedEndpoint => self::endpoint($index, $isDefaults[$index]),
            range(0, 2),
        ));

        // When
        $default = $endpoints->default();

        // Then
        static::assertSame($expected, $default->index);
    }

    /**
     * @return iterable<string, array{list<?bool>, int}>
     */
    public static function provideDefaults(): iterable
    {
        yield 'the first isDefault true' => [[false, true, true], 1];
        yield 'an isDefault true after one absent' => [[null, false, true], 2];
        yield 'else the first without isDefault false' => [[false, null, null], 1];
        yield 'else the first without isDefault false, false after it' => [[false, null, false], 1];
        yield 'else the first' => [[false, false, false], 0];
        yield 'all absent' => [[null, null, null], 0];
    }

    /**
     * M-9: no endpoint, no default.
     */
    #[Test]
    public function itHasNoDefaultWhenEmpty(): void
    {
        // Given
        $endpoints = new IndexedEndpoints([]);

        // Then
        $this->expectException(UnknownEndpoint::class);
        $this->expectExceptionMessageIs('The metadata lists no assertion consumer service (M-9).');

        // When
        $endpoints->default();
    }

    /**
     * M-9: the AssertionConsumerServiceIndex of a request names the endpoint of that index.
     */
    #[Test]
    public function itFindsAnEndpointByIndex(): void
    {
        // Given
        $endpoint = self::endpoint(7);
        $endpoints = new IndexedEndpoints([self::endpoint(3), $endpoint, self::endpoint(9)]);

        // When / Then
        static::assertSame($endpoint, $endpoints->byIndex(7));
    }

    /**
     * M-9, §9.2 row 30, "an AuthnRequest whose index the metadata does not list": UnknownEndpoint.
     */
    #[Test]
    public function itRefusesAnIndexItDoesNotList(): void
    {
        // Given
        $endpoints = new IndexedEndpoints([self::endpoint(3), self::endpoint(9)]);

        // Then
        $this->expectException(UnknownEndpoint::class);
        $this->expectExceptionMessageIs('No assertion consumer service of the metadata has that index (M-9).');

        // When
        $endpoints->byIndex(4);
    }

    /**
     * M-9: the AssertionConsumerServiceURL of a request names the first endpoint at that location.
     */
    #[Test]
    public function itFindsTheFirstEndpointByLocation(): void
    {
        // Given
        $endpoint = new IndexedEndpoint(Binding::HttpPost, 'https://sp.example.com/acs/two', 2);
        $endpoints = new IndexedEndpoints([
            new IndexedEndpoint(Binding::HttpPost, 'https://sp.example.com/acs/one', 1),
            $endpoint,
            new IndexedEndpoint(Binding::HttpPost, 'https://sp.example.com/acs/two', 3),
        ]);

        // When / Then
        static::assertSame($endpoint, $endpoints->byLocation('https://sp.example.com/acs/two'));
    }

    /**
     * M-8, M-9, §9.2 row 30, "an AuthnRequest whose AssertionConsumerServiceURL the metadata does not list":
     * compared exactly, no normalisation.
     */
    #[Test]
    #[DataProvider('provideLocationsNotListed')]
    public function itRefusesALocationItDoesNotList(string $location): void
    {
        // Given
        $endpoints = new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, 'https://sp.example.com/acs', 0)]);

        // Then
        $this->expectException(UnknownEndpoint::class);
        $this->expectExceptionMessageIs('No assertion consumer service of the metadata has that location (M-9).');

        // When
        $endpoints->byLocation($location);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLocationsNotListed(): iterable
    {
        yield 'another path' => ['https://sp.example.com/other'];
        yield 'a trailing slash' => ['https://sp.example.com/acs/'];
        yield 'another case in the host' => ['https://SP.example.com/acs'];
        yield 'a percent-encoded character' => ['https://sp.example.com/%61cs'];
    }

    private static function endpoint(int $index, ?bool $isDefault = null): IndexedEndpoint
    {
        return new IndexedEndpoint(Binding::HttpPost, 'https://sp.example.com/acs', $index, $isDefault);
    }

    /**
     * @return list<IndexedEndpoint>
     */
    private function endpoints(int $count): array
    {
        return array_map(self::endpoint(...), range(1, $count));
    }
}
