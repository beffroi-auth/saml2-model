<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Validation;

use Beffroi\Saml2\Model\Protocol\LogoutResponse;

/**
 * Its status is whichever the peer sent: a status other than Success, a partial logout included, is not a refusal.
 */
final readonly class AcceptedLogoutResponse
{
    public function __construct(
        public LogoutResponse $response,
        public Authentication $authentication,
    ) {
    }
}
