<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal;

use Beffroi\Saml2\Model\Internal\Window;
use Beffroi\Saml2\Model\Validation\TimeBounds;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * M-7: the edges of the windows, from now read once and the bounds of section 7, the one place every reader takes
 * them from.
 */
final class WindowTest extends TestCase
{
    /**
     * M-7: now plus the clock skew, the latest a NotBefore, an IssueInstant or an AuthnInstant may be.
     */
    #[Test]
    public function itGivesNowPlusTheSkewAsTheLatestInstant(): void
    {
        // When / Then
        static::assertSame('2026-09-30T12:02:00.500000', $this->window()->latest()->format('Y-m-d\TH:i:s.u'));
    }

    /**
     * M-7: now minus the clock skew, at or before which a NotOnOrAfter, a SessionNotOnOrAfter or a validUntil has
     * passed.
     */
    #[Test]
    public function itGivesNowMinusTheSkewAsTheEarliestInstant(): void
    {
        // When / Then
        static::assertSame('2026-09-30T11:58:00.500000', $this->window()->earliest()->format('Y-m-d\TH:i:s.u'));
    }

    /**
     * M-7: now minus maxMessageAge, the skew not added, before which an IssueInstant is too old.
     */
    #[Test]
    public function itGivesNowMinusTheMessageAgeAsTheOldestInstant(): void
    {
        // When / Then
        static::assertSame('2026-09-30T11:50:00.500000', $this->window()->oldest()->format('Y-m-d\TH:i:s.u'));
    }

    /**
     * M-7: now plus maxBearerWindow, the latest a bearer NotOnOrAfter may be.
     */
    #[Test]
    public function itGivesNowPlusTheBearerWindowAsItsLimit(): void
    {
        // When / Then
        static::assertSame('2026-09-30T12:15:00.500000', $this->window()->bearerLimit()->format('Y-m-d\TH:i:s.u'));
    }

    private function window(): Window
    {
        return new Window(
            new DateTimeImmutable('2026-09-30T12:00:00.500000Z'),
            new TimeBounds(clockSkew: 120, maxMessageAge: 600, maxBearerWindow: 900),
        );
    }
}
