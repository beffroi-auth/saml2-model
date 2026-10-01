<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Support;

use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.2, M-11: the replay port in memory, the double of the tests, keyed by the pair of the issuer and the ID.
 */
final class InMemoryReplayGuardTest extends TestCase
{
    /**
     * Section 5.2: a pair not seen yet is new, and remembered.
     */
    #[Test]
    public function itRemembersAPairItHasNotSeen(): void
    {
        // Given
        $guard = new InMemoryReplayGuard();

        // When
        $new = $guard->remember(
            'https://idp.example.com/saml',
            '_assertion',
            new DateTimeImmutable('2026-09-30T12:08:00Z'),
        );

        // Then
        static::assertTrue($new);
    }

    /**
     * §9.2 row 21, M-11: the same pair a second time is not new.
     */
    #[Test]
    public function itAnswersFalseForAPairItHasSeen(): void
    {
        // Given
        $guard = new InMemoryReplayGuard();
        $guard->remember('https://idp.example.com/saml', '_assertion', new DateTimeImmutable('2026-09-30T12:08:00Z'));

        // When
        $new = $guard->remember(
            'https://idp.example.com/saml',
            '_assertion',
            new DateTimeImmutable('2026-09-30T12:09:00Z'),
        );

        // Then
        static::assertFalse($new);
    }

    /**
     * §9.3 row 7, M-11: the key is the pair, so the same ID from another issuer is new.
     */
    #[Test]
    public function itRemembersTheSameIdFromAnotherIssuer(): void
    {
        // Given
        $guard = new InMemoryReplayGuard();
        $guard->remember('https://idp.example.com/saml', '_assertion', new DateTimeImmutable('2026-09-30T12:08:00Z'));

        // When
        $new = $guard->remember(
            'https://other-idp.example.com/saml',
            '_assertion',
            new DateTimeImmutable('2026-09-30T12:08:00Z'),
        );

        // Then
        static::assertTrue($new);
    }

    /**
     * M-11: another ID from the same issuer is new.
     */
    #[Test]
    public function itRemembersAnotherIdFromTheSameIssuer(): void
    {
        // Given
        $guard = new InMemoryReplayGuard();
        $guard->remember('https://idp.example.com/saml', '_assertion', new DateTimeImmutable('2026-09-30T12:08:00Z'));

        // When
        $new = $guard->remember(
            'https://idp.example.com/saml',
            '_other',
            new DateTimeImmutable('2026-09-30T12:08:00Z'),
        );

        // Then
        static::assertTrue($new);
    }

    /**
     * Section 5.2: when the pair may be forgotten, as it was first given; a second call changes nothing.
     */
    #[Test]
    public function itKeepsTheExpiryItWasFirstGiven(): void
    {
        // Given
        $guard = new InMemoryReplayGuard();
        $guard->remember('https://idp.example.com/saml', '_assertion', new DateTimeImmutable('2026-09-30T12:08:00Z'));
        $guard->remember('https://idp.example.com/saml', '_assertion', new DateTimeImmutable('2026-09-30T13:00:00Z'));

        // When
        $expiresAt = $guard->expiresAt('https://idp.example.com/saml', '_assertion');

        // Then
        static::assertSame('2026-09-30T12:08:00Z', $expiresAt?->format('Y-m-d\TH:i:s\Z'));
    }

    /**
     * Section 5.2: a pair never remembered has no expiry.
     */
    #[Test]
    public function itHasNoExpiryForAPairNeverRemembered(): void
    {
        // Given
        $guard = new InMemoryReplayGuard();
        $guard->remember('https://idp.example.com/saml', '_assertion', new DateTimeImmutable('2026-09-30T12:08:00Z'));

        // When / Then
        static::assertNull($guard->expiresAt('https://other-idp.example.com/saml', '_assertion'));
    }

    /**
     * M-11: a store nothing was remembered in is empty.
     */
    #[Test]
    public function itIsEmptyUntilAPairIsRemembered(): void
    {
        // When / Then
        static::assertTrue(new InMemoryReplayGuard()->isEmpty());
    }

    /**
     * M-11: a store holding a pair is not empty.
     */
    #[Test]
    public function itIsNotEmptyOnceAPairIsRemembered(): void
    {
        // Given
        $guard = new InMemoryReplayGuard();

        // When
        $guard->remember('https://idp.example.com/saml', '_assertion', new DateTimeImmutable('2026-09-30T12:08:00Z'));

        // Then
        static::assertFalse($guard->isEmpty());
    }
}
