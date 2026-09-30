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
 * What the rules of an AuthnRequest are checked against (section 6.2 steps 3 to 5), as the validator states it: the
 * window of M-7, from now read once from the clock and the time bounds of section 7; the service provider whose
 * metadata authenticated it and ours, the identity provider (M-8, M-9); the URL at which it arrived (M-8); how it was
 * authenticated (M-2), since a signature, of its own or of the binding, makes the Destination required.
 *
 * @internal outside the compatibility promise of section 5
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
