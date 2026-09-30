<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Support;

use DateTimeImmutable;
use DateTimeZone;
use Psr\Clock\ClockInterface;
use function sprintf;

/**
 * The clock port of section 5.2, frozen at an instant in UTC: now() returns it however often it is read. A test moves
 * time by taking another clock from movedBy(), never by sleeping (section 9.7); this one never changes.
 */
final readonly class FrozenClock implements ClockInterface
{
    private DateTimeImmutable $now;

    public function __construct(DateTimeImmutable $now)
    {
        $this->now = $now->setTimezone(new DateTimeZone('UTC'));
    }

    public function now(): DateTimeImmutable
    {
        return $this->now;
    }

    /**
     * A new clock, $seconds later, or earlier when negative.
     */
    public function movedBy(int $seconds): self
    {
        return new self($this->now->modify(sprintf('%+d seconds', $seconds)));
    }
}
