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
use Beffroi\Saml2\Model\Value\Uri;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Name;
use function count;
use Dom\Element;
use function preg_match;
use function sprintf;

/**
 * The endpoints of a role (section 6.5 step 6): each Binding a URI, those on HTTP-Redirect or HTTP-POST kept and any
 * other dropped, so that a real metadata listing Artifact or SOAP endpoints still loads; the assertion consumer
 * services kept on HTTP-POST only, their indexes unique over all of them, the dropped ones included.
 *
 * @internal
 */
final readonly class EndpointReader
{
    private const int MAX_ENDPOINTS = 64;

    private const int MAX_INDEX = 65_535;

    /**
     * @param list<Element> $elements the md:SingleSignOnService or md:SingleLogoutService children of a role
     * @param string $element their name in the schema
     *
     * @throws MalformedMessage when a Binding, a Location or a ResponseLocation is absent or not a URI (M-5, M-6)
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
     * @param list<Element> $elements the md:AssertionConsumerService children of a role
     *
     * @throws MalformedMessage when a Binding, a Location or an index is absent or not of its lexical form, two
     *                          share an index, or an isDefault is not a boolean (M-5, M-6)
     */
    public static function assertionConsumerServices(array $elements): IndexedEndpoints
    {
        $element = 'md:AssertionConsumerService';
        $indexes = [];
        $endpoints = [];
        foreach ($elements as $endpoint) {
            $binding = Uri::read(Schema::attribute($endpoint, $element, 'Binding'));
            $index = self::index(Schema::attribute($endpoint, $element, 'index'));
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
     * Section 7, before the endpoints of one kind are read: at most 64, the dropped ones counted.
     *
     * @param list<Element> $elements
     * @param string $element their name in the schema
     *
     * @throws LimitExceeded
     */
    public static function bound(array $elements, string $element): void
    {
        if (count($elements) > self::MAX_ENDPOINTS) {
            throw new LimitExceeded(sprintf(
                'A role descriptor holds more than 64 %s, the bound of section 7 (M-17).',
                $element,
            ));
        }
    }

    /**
     * An xs:unsignedShort in its one lexical form (M-6): decimal digits without sign, whitespace or leading zero, at
     * most 65535.
     *
     * @throws MalformedMessage
     */
    private static function index(string $index): int
    {
        if (preg_match('~^(?:0|[1-9]\d{0,4})\z~', $index) !== 1 || (int) $index > self::MAX_INDEX) {
            throw new MalformedMessage('An md:AssertionConsumerService index is not an xs:unsignedShort without sign or leading zero (M-6).');
        }

        return (int) $index;
    }
}
