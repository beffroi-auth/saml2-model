<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Metadata;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Uri;

/**
 * An indexed endpoint of a role (SAML Metadata §2.2.3): an assertion consumer service, its binding, its Location, a
 * URI of M-6, its index, an xs:unsignedShort, and its isDefault, null when the attribute is absent, which
 * IndexedEndpoints::default() tells apart from false.
 */
final readonly class IndexedEndpoint
{
    private const int MAX_INDEX = 65_535;

    /**
     * @throws MalformedMessage when the location is not a URI of M-6, or the index is not an xs:unsignedShort
     */
    public function __construct(
        public Binding $binding,
        public string $location,
        public int $index,
        public ?bool $isDefault = null,
    ) {
        Uri::read($location);
        if ($index < 0 || $index > self::MAX_INDEX) {
            throw new MalformedMessage('An index is not an xs:unsignedShort, from 0 to 65535 (M-6).');
        }
    }
}
