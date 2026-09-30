<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Assertion;

use Beffroi\Saml2\Model\Assertion\Conditions;
use Beffroi\Saml2\Model\Exception\AudienceMismatch;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3, M-7, M-8: the conditions of an assertion, a window that ends after it starts and at least one audience
 * restriction (SAML Core §2.5.1).
 */
final class ConditionsTest extends TestCase
{
    /**
     * Section 5.3: the window, the audiences of each restriction in their order, OneTimeUse, kept as given.
     */
    #[Test]
    public function itKeepsItsWindowAudiencesAndOneTimeUse(): void
    {
        // Given
        $notBefore = new DateTimeImmutable('2026-09-30T11:59:30Z');
        $notOnOrAfter = new DateTimeImmutable('2026-09-30T12:05:00Z');

        // When
        $conditions = new Conditions(
            $notBefore,
            $notOnOrAfter,
            [['https://sp.example.com/saml', 'urn:example:sp'], ['https://sp.example.com/saml']],
            true,
        );

        // Then
        static::assertSame(
            [
                $notBefore,
                $notOnOrAfter,
                [['https://sp.example.com/saml', 'urn:example:sp'], ['https://sp.example.com/saml']],
                true,
            ],
            [$conditions->notBefore, $conditions->notOnOrAfter, $conditions->audiences, $conditions->oneTimeUse],
        );
    }

    /**
     * SAML Core §2.5.1.2: either end of the window, or both, may be absent.
     */
    #[Test]
    #[DataProvider('provideOpenWindows')]
    public function itAcceptsAWindowOpenAtEitherEnd(?string $notBefore, ?string $notOnOrAfter): void
    {
        // When
        $conditions = new Conditions(
            $notBefore === null ? null : new DateTimeImmutable($notBefore),
            $notOnOrAfter === null ? null : new DateTimeImmutable($notOnOrAfter),
            [['https://sp.example.com/saml']],
            false,
        );

        // Then
        static::assertSame(
            [$notBefore, $notOnOrAfter],
            [$conditions->notBefore?->format('Y-m-d\TH:i:s\Z'), $conditions->notOnOrAfter?->format('Y-m-d\TH:i:s\Z')],
        );
    }

    /**
     * @return iterable<string, array{?string, ?string}>
     */
    public static function provideOpenWindows(): iterable
    {
        yield 'no end' => [null, null];
        yield 'NotBefore only' => ['2026-09-30T11:59:30Z', null];
        yield 'NotOnOrAfter only' => [null, '2026-09-30T12:05:00Z'];
        yield 'one second wide' => ['2026-09-30T12:04:59Z', '2026-09-30T12:05:00Z'];
    }

    /**
     * §9.2 row 19, M-7, SAML Core §2.5.1.2: the interval ends at NotOnOrAfter, so a NotBefore equal to it, or later,
     * leaves no instant at which the assertion is valid.
     */
    #[Test]
    #[DataProvider('provideEmptyWindows')]
    public function itRefusesAWindowThatDoesNotEndAfterItStarts(string $notBefore): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The NotBefore of the Conditions is not earlier than their NotOnOrAfter (M-7).');

        // When
        new Conditions(
            new DateTimeImmutable($notBefore),
            new DateTimeImmutable('2026-09-30T12:05:00Z'),
            [['https://sp.example.com/saml']],
            false,
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideEmptyWindows(): iterable
    {
        yield 'NotBefore equal to NotOnOrAfter' => ['2026-09-30T12:05:00Z'];
        yield 'NotBefore a second later' => ['2026-09-30T12:05:01Z'];
    }

    /**
     * §9.2 row 15, M-8, SAML Profiles §4.1.4.2: an assertion of the Web Browser SSO profile carries at least one
     * AudienceRestriction.
     */
    #[Test]
    public function itRefusesNoAudienceRestriction(): void
    {
        // Then
        $this->expectException(AudienceMismatch::class);
        $this->expectExceptionMessageIs('The Conditions hold no AudienceRestriction (M-8).');

        // When
        new Conditions(null, null, [], false);
    }

    /**
     * M-5, SAML Core §2.5.1.4: an AudienceRestriction holds one Audience or more.
     */
    #[Test]
    public function itRefusesARestrictionWithoutAudience(): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('An AudienceRestriction holds no Audience (M-5).');

        // When
        new Conditions(null, null, [['https://sp.example.com/saml'], []], false);
    }

    /**
     * §9.2 row 26, M-6: an Audience relative/path, in any restriction; the message carries nothing of it (M-16).
     */
    #[Test]
    public function itRefusesAnAudienceThatIsNotAUri(): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A URI is not absolute (M-6).');

        // When
        new Conditions(
            null,
            null,
            [['https://sp.example.com/saml'], ['https://sp.example.com/saml', 'relative/path']],
            false,
        );
    }
}
