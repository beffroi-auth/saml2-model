<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Validation;

use InvalidArgumentException;
use function sprintf;

/**
 * The time bounds of section 7, in seconds (M-7).
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
