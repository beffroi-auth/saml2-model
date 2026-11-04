<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal;

use Beffroi\Saml2\Model\Validation\TimeBounds;
use DateTimeImmutable;
use function sprintf;

/**
 * M-7
 *
 * @internal
 */
final readonly class Window
{
    public function __construct(
        public DateTimeImmutable $now,
        public TimeBounds $bounds,
    ) {
    }

    public function latest(): DateTimeImmutable
    {
        return $this->now->modify(sprintf('+%d seconds', $this->bounds->clockSkew));
    }

    public function earliest(): DateTimeImmutable
    {
        return $this->now->modify(sprintf('-%d seconds', $this->bounds->clockSkew));
    }

    /**
     * Now minus maxMessageAge, the skew not added (M-7).
     */
    public function oldest(): DateTimeImmutable
    {
        return $this->now->modify(sprintf('-%d seconds', $this->bounds->maxMessageAge));
    }

    /**
     * The skew is added since Entra ends its bearer window exactly maxBearerWindow after it issues: without it, a
     * service provider whose clock is one second behind Entra's would refuse every response.
     */
    public function bearerLimit(): DateTimeImmutable
    {
        return $this->now->modify(sprintf('+%d seconds', $this->bounds->maxBearerWindow + $this->bounds->clockSkew));
    }
}
