<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Assertion;

use Beffroi\Saml2\Model\Internal\Window;
use Beffroi\Saml2\Model\Validation\TimeBounds;
use DateTimeImmutable;

/**
 * @internal
 */
final readonly class AssertionContext
{
    public Window $window;

    public function __construct(
        DateTimeImmutable $now,
        TimeBounds $bounds,
        public string $identityProvider,
        public string $audience,
        public string $recipient,
        public ?string $inResponseTo,
    ) {
        $this->window = new Window($now, $bounds);
    }
}
