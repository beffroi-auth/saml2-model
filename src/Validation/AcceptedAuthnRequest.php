<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Validation;

use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;

/**
 * An AuthnRequest the identity provider accepted (section 5.6): the request, its values copied out of the document
 * that was verified or authenticated (M-1); the assertion consumer service it resolves to in the service provider's
 * metadata, the one endpoint the response may go to (M-9); and how the request was authenticated (M-2). What
 * happens next, a login or a failure response to that endpoint, is the consumer's (section 6.2 step 6).
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
