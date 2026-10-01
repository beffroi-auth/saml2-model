<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Assertion;

use Beffroi\Saml2\Model\Internal\Window;
use Beffroi\Saml2\Model\Validation\TimeBounds;
use DateTimeImmutable;

/**
 * What the rules of an assertion are checked against (section 6.1 steps 7 to 11), as the validator states it: the
 * window of M-7, from now read once from the clock and the time bounds of section 7; the entity ID of the identity provider whose keys verified
 * the assertion and ours, its audience (M-8); the URL at which the response arrived, its recipient (M-8); the ID of the
 * request it answers, or null for an unsolicited response (M-10).
 *
 * @internal outside the compatibility promise of section 5
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
