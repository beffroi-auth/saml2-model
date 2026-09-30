<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Validation;

use InvalidArgumentException;
use function sprintf;

/**
 * The three time bounds of section 7, in seconds, which the validators and the metadata reader share (M-7): the clock
 * skew, how old an IssueInstant may be when a message arrives, how far ahead a bearer NotOnOrAfter may be. Each is a
 * quantity a caller may raise up to its ceiling for a documented reason, never a switch that removes a window.
 */
final readonly class TimeBounds
{
    private const int CLOCK_SKEW_CEILING = 300;

    private const int MAX_MESSAGE_AGE_CEILING = 3_600;

    private const int MAX_BEARER_WINDOW_CEILING = 86_400;

    /**
     * @throws InvalidArgumentException when a value is under 1 or over the ceiling of section 7
     */
    public function __construct(
        public int $clockSkew = 180,
        public int $maxMessageAge = 300,
        public int $maxBearerWindow = 3_600,
    ) {
        $this->check('clockSkew', $clockSkew, self::CLOCK_SKEW_CEILING);
        $this->check('maxMessageAge', $maxMessageAge, self::MAX_MESSAGE_AGE_CEILING);
        $this->check('maxBearerWindow', $maxBearerWindow, self::MAX_BEARER_WINDOW_CEILING);
    }

    private function check(string $bound, int $seconds, int $ceiling): void
    {
        if ($seconds < 1 || $seconds > $ceiling) {
            throw new InvalidArgumentException(sprintf(
                '%s must be between 1 and %d seconds (section 7).',
                $bound,
                $ceiling,
            ));
        }
    }
}
