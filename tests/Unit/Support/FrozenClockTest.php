<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Support;

use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 9.7, M-7: the frozen clock of the tests, the only time they read.
 */
final class FrozenClockTest extends TestCase
{
    /**
     * Section 5.2: the instant it was built on, in UTC, whatever zone it was given.
     */
    #[Test]
    public function itReadsTheInstantItIsFrozenAtInUtc(): void
    {
        // Given
        $clock = new FrozenClock(
            new DateTimeImmutable('2026-09-30T12:00:00.250000Z')->setTimezone(new DateTimeZone('Europe/Paris')),
        );

        // When
        $now = $clock->now();

        // Then
        static::assertSame(
            ['2026-09-30T12:00:00.250000', 'UTC'],
            [$now->format('Y-m-d\TH:i:s.u'), $now->getTimezone()->getName()],
        );
    }

    /**
     * Section 9.7: a test never sleeps, it takes a clock moved by a number of seconds, forward or back.
     */
    #[Test]
    #[DataProvider('provideMoves')]
    public function itGivesAClockMovedByANumberOfSeconds(int $seconds, string $expected): void
    {
        // Given
        $clock = new FrozenClock(new DateTimeImmutable('2026-09-30T12:00:00.250000Z'));

        // When
        $moved = $clock->movedBy($seconds);

        // Then
        static::assertSame($expected, $moved->now()->format('Y-m-d\TH:i:s.u'));
    }

    /**
     * @return iterable<string, array{int, string}>
     */
    public static function provideMoves(): iterable
    {
        yield 'a second later' => [1, '2026-09-30T12:00:01.250000'];
        yield 'an hour and a second later' => [3_601, '2026-09-30T13:00:01.250000'];
        yield 'three minutes earlier' => [-180, '2026-09-30T11:57:00.250000'];
    }

    /**
     * Section 9.7: moving gives another clock; the one a validator already holds stays where it was.
     */
    #[Test]
    public function itDoesNotMoveItself(): void
    {
        // Given
        $clock = new FrozenClock(new DateTimeImmutable('2026-09-30T12:00:00Z'));

        // When
        $clock->movedBy(60);

        // Then
        static::assertSame('2026-09-30T12:00:00', $clock->now()->format('Y-m-d\TH:i:s'));
    }
}
