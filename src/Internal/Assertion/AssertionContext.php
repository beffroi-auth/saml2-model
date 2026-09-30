<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Assertion;

use Beffroi\Saml2\Model\Validation\TimeBounds;
use DateTimeImmutable;
use function sprintf;

/**
 * What the rules of an assertion are checked against (section 6.1 steps 7 to 11), as the validator states it: now, read
 * once from the clock (M-7); the time bounds of section 7; the entity ID of the identity provider whose keys verified
 * the assertion and ours, its audience (M-8); the URL at which the response arrived, its recipient (M-8); the ID of the
 * request it answers, or null for an unsolicited response (M-10).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class AssertionContext
{
    public function __construct(
        public DateTimeImmutable $now,
        public TimeBounds $bounds,
        public string $identityProvider,
        public string $audience,
        public string $recipient,
        public ?string $inResponseTo,
    ) {
    }

    /**
     * Now plus the clock skew: a NotBefore, an IssueInstant or an AuthnInstant later than this is refused (M-7).
     */
    public function latest(): DateTimeImmutable
    {
        return $this->now->modify(sprintf('+%d seconds', $this->bounds->clockSkew));
    }

    /**
     * Now minus the clock skew: a NotOnOrAfter or a SessionNotOnOrAfter at or before this is refused (M-7).
     */
    public function earliest(): DateTimeImmutable
    {
        return $this->now->modify(sprintf('-%d seconds', $this->bounds->clockSkew));
    }

    /**
     * Now plus maxBearerWindow: a bearer NotOnOrAfter later than this is refused (M-7).
     */
    public function bearerLimit(): DateTimeImmutable
    {
        return $this->now->modify(sprintf('+%d seconds', $this->bounds->maxBearerWindow));
    }
}
