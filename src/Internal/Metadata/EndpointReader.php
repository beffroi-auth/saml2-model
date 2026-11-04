<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Metadata;

use function array_key_exists;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Value\Boolean;
use Beffroi\Saml2\Model\Value\Counts;
use Beffroi\Saml2\Model\Value\UnsignedShort;
use Beffroi\Saml2\Model\Value\Uri;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Name;
use function count;
use Dom\Element;
use function sprintf;

/**
 * Section 6.5 step 6
 *
 * Endpoints on other bindings are dropped, not refused, so that real metadata listing them still loads.
 *
 * @internal
 */
final readonly class EndpointReader
{
    /**
     * @param list<Element> $elements
     * @param string $element their name in the schema
     *
     * @throws MalformedMessage
     *
     * @return list<Endpoint> those on HTTP-Redirect or HTTP-POST, in order
     */
    public static function endpoints(array $elements, string $element): array
    {
        $endpoints = [];
        foreach ($elements as $endpoint) {
            $binding = Binding::tryFrom(Uri::read(Schema::attribute($endpoint, $element, 'Binding')));
            if ($binding === null) {
                continue;
            }
            $endpoints[] = new Endpoint(
                $binding,
                Schema::attribute($endpoint, $element, 'Location'),
                Attributes::optional($endpoint, new Name(null, 'ResponseLocation')),
            );
        }

        return $endpoints;
    }

    /**
     * @param list<Element> $elements
     *
     * @throws MalformedMessage
     */
    public static function assertionConsumerServices(array $elements): IndexedEndpoints
    {
        $element = 'md:AssertionConsumerService';
        $indexes = [];
        $endpoints = [];
        foreach ($elements as $endpoint) {
            $binding = Uri::read(Schema::attribute($endpoint, $element, 'Binding'));
            $index = UnsignedShort::read(Schema::attribute($endpoint, $element, 'index'));
            if (array_key_exists($index, $indexes)) {
                throw new MalformedMessage('Two md:AssertionConsumerService of a role share an index (section 6.5).');
            }
            $indexes[$index] = $endpoint;
            if ($binding !== Binding::HttpPost->value) {
                continue;
            }
            $isDefault = Attributes::optional($endpoint, new Name(null, 'isDefault'));
            $endpoints[] = new IndexedEndpoint(
                Binding::HttpPost,
                Schema::attribute($endpoint, $element, 'Location'),
                $index,
                $isDefault === null ? null : Boolean::read($isDefault),
            );
        }

        return new IndexedEndpoints($endpoints);
    }

    /**
     * Section 7
     *
     * @param list<Element> $elements
     * @param string $element their name in the schema
     *
     * @throws LimitExceeded
     */
    public static function bound(array $elements, string $element): void
    {
        Counts::check(
            count($elements),
            Counts::ENDPOINTS,
            sprintf('A role descriptor holds more than 64 %s, the bound of section 7 (M-17).', $element),
        );
    }
}
