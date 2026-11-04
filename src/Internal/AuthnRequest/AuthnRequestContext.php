<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\AuthnRequest;

use Beffroi\Saml2\Model\Internal\Window;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Validation\TimeBounds;
use DateTimeImmutable;

/**
 * @internal
 */
final readonly class AuthnRequestContext
{
    public Window $window;

    public function __construct(
        DateTimeImmutable $now,
        TimeBounds $bounds,
        public ServiceProvider $serviceProvider,
        public IdentityProvider $identityProvider,
        public string $receivedAt,
        public Authentication $authentication,
    ) {
        $this->window = new Window($now, $bounds);
    }
}
