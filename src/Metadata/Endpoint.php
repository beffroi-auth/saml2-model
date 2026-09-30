<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Metadata;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Uri;

/**
 * An endpoint of a role (SAML Metadata §2.2.2): a single sign-on or a single logout service, its binding, its
 * Location and its optional ResponseLocation, each a URI of M-6, compared as read (M-8).
 */
final readonly class Endpoint
{
    /**
     * @throws MalformedMessage when the location or the response location is not a URI of M-6
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
