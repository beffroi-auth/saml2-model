<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion;

use Beffroi\Saml2\Model\Internal\Assertion\AssertionContext;
use Beffroi\Saml2\Model\Validation\TimeBounds;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * M-7, section 6.1 steps 7 to 11: the edges of the windows, from now read once and the bounds of section 7.
 */
final class AssertionContextTest extends TestCase
{
    /**
     * M-7: now plus the clock skew, the latest a NotBefore, an IssueInstant or an AuthnInstant may be.
     */
    #[Test]
    public function itGivesNowPlusTheSkewAsTheLatestInstant(): void
    {
        // When / Then
        static::assertSame('2026-09-30T12:02:00.500000', $this->context()->latest()->format('Y-m-d\TH:i:s.u'));
    }

    /**
     * M-7: now minus the clock skew, at or before which a NotOnOrAfter or a SessionNotOnOrAfter has passed.
     */
    #[Test]
    public function itGivesNowMinusTheSkewAsTheEarliestInstant(): void
    {
        // When / Then
        static::assertSame('2026-09-30T11:58:00.500000', $this->context()->earliest()->format('Y-m-d\TH:i:s.u'));
    }

    /**
     * M-7: now plus maxBearerWindow, the latest a bearer NotOnOrAfter may be.
     */
    #[Test]
    public function itGivesNowPlusTheBearerWindowAsItsLimit(): void
    {
        // When / Then
        static::assertSame('2026-09-30T12:15:00.500000', $this->context()->bearerLimit()->format('Y-m-d\TH:i:s.u'));
    }

    private function context(): AssertionContext
    {
        return new AssertionContext(
            new DateTimeImmutable('2026-09-30T12:00:00.500000Z'),
            new TimeBounds(clockSkew: 120, maxBearerWindow: 900),
            'https://idp.example.com/saml',
            'https://sp.example.com/saml',
            'https://sp.example.com/saml/acs',
            null,
        );
    }
}
