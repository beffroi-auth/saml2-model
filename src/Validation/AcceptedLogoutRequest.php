<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Validation;

use Beffroi\Saml2\Model\Protocol\LogoutRequest;

/**
 * A samlp:LogoutRequest that the rules of section 6.3 accepted (section 5.6), its values copied out of what its
 * signature or its binding authenticated, and how it was authenticated (M-2). Whether its NameID and its session
 * indexes name a session is the consumer's (SAML Core §3.7.3).
 */
final readonly class AcceptedLogoutRequest
{
    public function __construct(
        public LogoutRequest $request,
        public Authentication $authentication,
    ) {
    }
}
