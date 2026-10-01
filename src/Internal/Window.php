<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal;

use Beffroi\Saml2\Model\Validation\TimeBounds;
use DateTimeImmutable;
use function sprintf;

/**
 * The edges of the windows of M-7, the one place every reader takes them from: now, read once per validation from the
 * clock the consumer passes, and the time bounds of section 7.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Window
{
    public function __construct(
        public DateTimeImmutable $now,
        public TimeBounds $bounds,
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
     * Now minus the clock skew: a NotOnOrAfter, a SessionNotOnOrAfter or a validUntil at or before this is refused
     * (M-7).
     */
    public function earliest(): DateTimeImmutable
    {
        return $this->now->modify(sprintf('-%d seconds', $this->bounds->clockSkew));
    }

    /**
     * Now minus maxMessageAge, the skew not added: an IssueInstant earlier than this is refused (M-7).
     */
    public function oldest(): DateTimeImmutable
    {
        return $this->now->modify(sprintf('-%d seconds', $this->bounds->maxMessageAge));
    }

    /**
     * Now plus maxBearerWindow: a bearer NotOnOrAfter later than this is refused (M-7).
     */
    public function bearerLimit(): DateTimeImmutable
    {
        return $this->now->modify(sprintf('+%d seconds', $this->bounds->maxBearerWindow));
    }
}
