<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Metadata;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\UnsignedShort;
use Beffroi\Saml2\Model\Value\Uri;

/**
 * SAML Metadata §2.2.3
 */
final readonly class IndexedEndpoint
{
    /**
     * @throws MalformedMessage
     */
    public function __construct(
        public Binding $binding,
        public string $location,
        public int $index,
        public ?bool $isDefault = null,
    ) {
        Uri::read($location);
        UnsignedShort::check($index);
    }
}
