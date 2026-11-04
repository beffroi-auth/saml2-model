<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Validation;

use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;

/**
 * Its assertion consumer service, resolved in the service provider's metadata, is the one endpoint the response may
 * go to (M-9).
 */
final readonly class AcceptedAuthnRequest
{
    public function __construct(
        public AuthnRequest $request,
        public IndexedEndpoint $assertionConsumerService,
        public Authentication $authentication,
    ) {
    }
}
