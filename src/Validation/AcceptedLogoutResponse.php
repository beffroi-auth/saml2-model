<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Validation;

use Beffroi\Saml2\Model\Protocol\LogoutResponse;

/**
 * A samlp:LogoutResponse that the rules of section 6.4 accepted (section 5.6), its values copied out of what its
 * signature or its binding authenticated, and how it was authenticated (M-2). Its status is whichever the peer sent:
 * a status other than Success, a partial logout included, is the answer to a request that was ours, not a refusal.
 */
final readonly class AcceptedLogoutResponse
{
    public function __construct(
        public LogoutResponse $response,
        public Authentication $authentication,
    ) {
    }
}
