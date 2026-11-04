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
 * The assertion consumer services of a service provider (M-9, SAML Metadata §2.2.3).
 */
final readonly class IndexedEndpoints
{
    /**
     * @param list<IndexedEndpoint> $endpoints
     *
     * @throws LimitExceeded
     * @throws Unsupported when one is not on HTTP-POST
     * @throws MalformedMessage when two share an index
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
     * SAML Metadata §2.2.3
     *
     * @throws UnknownEndpoint
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
     * @throws UnknownEndpoint
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
     * M-8
     *
     * @throws UnknownEndpoint
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
