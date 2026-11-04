<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Metadata;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Uri;

/**
 * SAML Metadata §2.2.2
 */
final readonly class Endpoint
{
    /**
     * @throws MalformedMessage
     */
    public function __construct(
        public Binding $binding,
        public string $location,
        public ?string $responseLocation = null,
    ) {
        Uri::read($location);
        if ($responseLocation !== null) {
            Uri::read($responseLocation);
        }
    }
}
