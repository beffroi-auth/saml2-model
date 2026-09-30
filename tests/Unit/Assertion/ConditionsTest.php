<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Assertion;

use function array_fill;
use Beffroi\Saml2\Model\Assertion\Conditions;
use Beffroi\Saml2\Model\Exception\AudienceMismatch;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
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

    /**
     * Section 7, M-15, M-17: 8 AudienceRestriction of 16 Audience each, the bounds the reader of the service provider
     * applies, are the most the Conditions hold whoever builds them.
     */
    #[Test]
    public function itHoldsTheBoundsOfSection7(): void
    {
        // Given
        $audiences = array_fill(0, 8, array_fill(0, 16, 'https://sp.example.com/saml'));

        // When
        $conditions = new Conditions(null, null, $audiences, false);

        // Then
        static::assertSame($audiences, $conditions->audiences);
    }

    /**
     * §9.2 row 36, M-15, M-17: one restriction or one audience over its bound of section 7, which the reader of the
     * service provider would refuse, is refused whoever builds the Conditions, a writer included.
     *
     * @param list<list<string>> $audiences
     */
    #[Test]
    #[DataProvider('provideAudiencesOverTheirBound')]
    public function itRefusesAudiencesOverTheirBound(array $audiences, string $message): void
    {
        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs($message);

        // When
        new Conditions(null, null, $audiences, false);
    }

    /**
     * @return iterable<string, array{list<list<string>>, string}>
     */
    public static function provideAudiencesOverTheirBound(): iterable
    {
        yield '9 AudienceRestriction' => [
            array_fill(0, 9, ['https://sp.example.com/saml']),
            'The Conditions hold more than 8 AudienceRestriction, the bound of section 7 (M-17).',
        ];
        yield '17 Audience in one restriction' => [
            [['https://sp.example.com/saml'], array_fill(0, 17, 'https://sp.example.com/saml')],
            'An AudienceRestriction holds more than 16 Audience, the bound of section 7 (M-17).',
        ];
    }
}
