<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Validation;

use Beffroi\Saml2\Model\Protocol\LogoutRequest;

final readonly class AcceptedLogoutRequest
{
    public function __construct(
        public LogoutRequest $request,
        public Authentication $authentication,
    ) {
    }
}
