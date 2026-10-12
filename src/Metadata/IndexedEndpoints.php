<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Metadata;

use function array_key_exists;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\UnknownEndpoint;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Value\Counts;
use function count;

/**
 * The assertion consumer services of a service provider (section 5.3, M-9): at most 64, their indexes unique (SAML
 * Metadata §2.2.3), each on HTTP-POST, the one binding a response is sent over (section 8), in the order of the
 * metadata. The metadata reader drops the others before it builds the list, and whoever else builds it, from the
 * metadata it stored, cannot put one in, so that the three searches below never establish an endpoint of another
 * binding (section 6.5 step 6); a search that finds nothing is UnknownEndpoint.
 */
final readonly class IndexedEndpoints
{
    /**
     * @param list<IndexedEndpoint> $endpoints
     *
     * @throws LimitExceeded when there are more than 64 (section 7)
     * @throws Unsupported when one is not on HTTP-POST (section 8)
     * @throws MalformedMessage when two share an index (SAML Metadata §2.2.3)
     */
    public function __construct(
        public array $endpoints,
    ) {
        Counts::check(
            count($endpoints),
            Counts::ENDPOINTS,
            'A role holds more than 64 assertion consumer services, the bound of section 7 (M-17).',
        );
        $byIndex = [];
        foreach ($endpoints as $endpoint) {
            if ($endpoint->binding !== Binding::HttpPost) {
                throw new Unsupported('An assertion consumer service is not on HTTP-POST, the one binding the package answers over (section 8).');
            }
            if (array_key_exists($endpoint->index, $byIndex)) {
                throw new MalformedMessage('Two assertion consumer services share an index (section 6.5).');
            }
            $byIndex[$endpoint->index] = $endpoint;
        }
    }

    /**
     * The default endpoint of SAML Metadata §2.2.3: the first whose isDefault is true; else the first without an
     * isDefault of false; else the first.
     *
     * @throws UnknownEndpoint when the list is empty (M-9)
     */
    public function default(): IndexedEndpoint
    {
        foreach ($this->endpoints as $endpoint) {
            if ($endpoint->isDefault === true) {
                return $endpoint;
            }
        }
        foreach ($this->endpoints as $endpoint) {
            if ($endpoint->isDefault !== false) {
                return $endpoint;
            }
        }

        return $this->endpoints[0] ?? throw new UnknownEndpoint('The metadata lists no assertion consumer service (M-9).');
    }

    /**
     * The endpoint of the AssertionConsumerServiceIndex of a request.
     *
     * @throws UnknownEndpoint when no endpoint of the list has that index (M-9)
     */
    public function byIndex(int $index): IndexedEndpoint
    {
        foreach ($this->endpoints as $endpoint) {
            if ($endpoint->index === $index) {
                return $endpoint;
            }
        }

        throw new UnknownEndpoint('No assertion consumer service of the metadata has that index (M-9).');
    }

    /**
     * The first endpoint whose Location is the AssertionConsumerServiceURL of a request, compared exactly (M-8).
     *
     * @throws UnknownEndpoint when no endpoint of the list has that location (M-9)
     */
    public function byLocation(string $location): IndexedEndpoint
    {
        foreach ($this->endpoints as $endpoint) {
            if ($endpoint->location === $location) {
                return $endpoint;
            }
        }

        throw new UnknownEndpoint('No assertion consumer service of the metadata has that location (M-9).');
    }
}
