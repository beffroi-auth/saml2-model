<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion;

use Beffroi\Saml2\Model\Exception\AudienceMismatch;
use Beffroi\Saml2\Model\Exception\IndeterminateCondition;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Assertion\ConditionsReader;
use function array_fill;
use function array_map;
use function count;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.1 step 9, M-7, M-8, M-13: the conditions of an assertion, their window, their audience restrictions and
 * OneTimeUse, and nothing else (SAML Core §2.5.1).
 */
final class ConditionsReaderTest extends TestCase
{
    use AssertionFixtures;

    /**
     * Section 5.3: the window, the audiences of the restriction and no OneTimeUse, as read.
     */
    #[Test]
    public function itReadsTheWindowAndTheAudiences(): void
    {
        // Given
        $conditions = $this->child($this->document('behaviour/assertion-valid-accepted.xml'), 'Conditions');

        // When
        $read = ConditionsReader::read($conditions, $this->context());

        // Then
        static::assertSame(
            ['2026-09-30T11:59:28Z', '2026-09-30T12:04:58Z', [['https://sp.example.com/saml']], false],
            [
                $read->notBefore?->format('Y-m-d\TH:i:s\Z'),
                $read->notOnOrAfter?->format('Y-m-d\TH:i:s\Z'),
                $read->audiences,
                $read->oneTimeUse,
            ],
        );
    }

    /**
     * SAML Core §2.5.1.2: Conditions without NotBefore or NotOnOrAfter are open at both ends.
     */
    #[Test]
    public function itReadsConditionsWithoutAWindow(): void
    {
        // Given
        $conditions = $this->child(
            $this->document('behaviour/assertion-conditions-without-window-accepted.xml'),
            'Conditions',
        );

        // When
        $read = ConditionsReader::read($conditions, $this->context());

        // Then
        static::assertSame([null, null], [$read->notBefore, $read->notOnOrAfter]);
    }

    /**
     * §9.3 row 6, M-7: a NotBefore at now plus the skew, and a NotOnOrAfter one second after now minus the skew, the
     * edges of the window, are accepted.
     */
    #[Test]
    #[DataProvider('provideWindowEdges')]
    public function itAcceptsTheEdgesOfTheWindow(string $fixture, ?string $notBefore, ?string $notOnOrAfter): void
    {
        // Given
        $conditions = $this->child($this->document($fixture), 'Conditions');

        // When
        $read = ConditionsReader::read($conditions, $this->context());

        // Then
        static::assertSame(
            [$notBefore, $notOnOrAfter],
            [$read->notBefore?->format('Y-m-d\TH:i:s\Z'), $read->notOnOrAfter?->format('Y-m-d\TH:i:s\Z')],
        );
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideWindowEdges(): iterable
    {
        yield 'NotBefore at now plus the skew' => [
            'behaviour/assertion-conditions-not-before-at-skew-accepted.xml',
            '2026-09-30T12:03:00Z',
            '2026-09-30T12:04:58Z',
        ];
        yield 'NotOnOrAfter a second after now minus the skew' => [
            'behaviour/assertion-conditions-not-on-or-after-after-skew-accepted.xml',
            '2026-09-30T11:55:00Z',
            '2026-09-30T11:57:01Z',
        ];
    }

    /**
     * §9.2 row 18, M-7: the Conditions NotOnOrAfter at now minus the skew; the NotBefore at now plus the skew plus one
     * second; each message names its window.
     */
    #[Test]
    #[DataProvider('provideWindowsOutside')]
    public function itRefusesConditionsOutsideTheirWindow(string $fixture, string $message): void
    {
        // Given
        $document = $this->document($fixture);

        // Then
        $this->expectException(OutsideValidityWindow::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        ConditionsReader::read($this->child($document, 'Conditions'), $this->context());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideWindowsOutside(): iterable
    {
        yield 'NotOnOrAfter at now minus the skew' => [
            'hostile/assertion-conditions-not-on-or-after-at-skew-refused.xml',
            'The NotOnOrAfter of the Conditions is at or before now minus the clock skew (M-7).',
        ];
        yield 'NotBefore a second beyond now plus the skew' => [
            'hostile/assertion-conditions-not-before-beyond-skew-refused.xml',
            'The NotBefore of the Conditions is later than now plus the clock skew (M-7).',
        ];
    }

    /**
     * §9.2 row 19, M-7, SAML Core §2.5.1.2: NotBefore equal to NotOnOrAfter.
     */
    #[Test]
    public function itRefusesANotBeforeEqualToTheNotOnOrAfter(): void
    {
        // Given
        $document = $this->document('hostile/assertion-conditions-not-before-equal-not-on-or-after-refused.xml');
        $message = 'The NotBefore of the Conditions is not earlier than their NotOnOrAfter (M-7).';

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        ConditionsReader::read($this->child($document, 'Conditions'), $this->context());
    }

    /**
     * §9.3 row 5, M-8, E46: two AudienceRestriction, each holding ours among others; the audiences are kept as read.
     */
    #[Test]
    public function itAcceptsTwoRestrictionsBothHoldingOurs(): void
    {
        // Given
        $conditions = $this->child(
            $this->document('behaviour/assertion-two-audience-restrictions-both-ours-accepted.xml'),
            'Conditions',
        );

        // When
        $read = ConditionsReader::read($conditions, $this->context());

        // Then
        static::assertSame(
            [
                ['https://other-sp.example.com/saml', 'https://sp.example.com/saml'],
                ['https://sp.example.com/saml',       'urn:example:federation'],
            ],
            $read->audiences,
        );
    }

    /**
     * §9.2 row 15, M-8, E46: an Audience other than ours; two AudienceRestriction, one without ours; no
     * AudienceRestriction.
     */
    #[Test]
    #[DataProvider('provideAudienceMismatches')]
    public function itRefusesARestrictionWithoutOurs(string $fixture, string $message): void
    {
        // Given
        $document = $this->document($fixture);

        // Then
        $this->expectException(AudienceMismatch::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        ConditionsReader::read($this->child($document, 'Conditions'), $this->context());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideAudienceMismatches(): iterable
    {
        yield 'an Audience other than ours' => [
            'hostile/assertion-audience-another-sp-refused.xml',
            'An AudienceRestriction does not hold our entity ID among its audiences (M-8).',
        ];
        yield 'two AudienceRestriction, one without ours' => [
            'hostile/assertion-two-audience-restrictions-one-without-ours-refused.xml',
            'An AudienceRestriction does not hold our entity ID among its audiences (M-8).',
        ];
        yield 'no AudienceRestriction' => [
            'hostile/assertion-without-audience-restriction-refused.xml',
            'The Conditions hold no AudienceRestriction (M-8).',
        ];
    }

    /**
     * §9.2 rows 25 and 26, M-5, M-6: an Audience relative/path next to ours; an AudienceRestriction without Audience,
     * or holding another element; two OneTimeUse (SAML Core §2.5.1.5).
     */
    #[Test]
    #[DataProvider('provideMalformedConditions')]
    public function itRefusesMalformedConditions(string $fixture, string $message): void
    {
        // Given
        $document = $this->document($fixture);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        ConditionsReader::read($this->child($document, 'Conditions'), $this->context());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMalformedConditions(): iterable
    {
        yield 'an Audience relative/path' => [
            'hostile/assertion-audience-relative-path-refused.xml',
            'A URI is not absolute (M-6).',
        ];
        yield 'an AudienceRestriction without Audience' => [
            'hostile/assertion-audience-restriction-without-audience-refused.xml',
            'The saml:AudienceRestriction holds no saml:Audience (M-4).',
        ];
        yield 'an AudienceRestriction holding another element' => [
            'hostile/assertion-audience-restriction-unknown-child-refused.xml',
            'The saml:AudienceRestriction holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
        yield 'two OneTimeUse' => [
            'hostile/assertion-two-one-time-use-refused.xml',
            'The Conditions hold more than one saml:OneTimeUse (M-5).',
        ];
    }

    /**
     * Section 5.3, M-11, SAML Core §2.5.1.5: one OneTimeUse, which the replay rule already honours.
     */
    #[Test]
    public function itReadsOneTimeUse(): void
    {
        // Given
        $conditions = $this->child($this->document('behaviour/assertion-one-time-use-accepted.xml'), 'Conditions');

        // When / Then
        static::assertTrue(ConditionsReader::read($conditions, $this->context())->oneTimeUse);
    }

    /**
     * §9.2 row 23, M-13, SAML Core §2.5.1.1: a saml:Condition with an xsi:type, or any other element, is a condition
     * the package does not understand; the assertion is Indeterminate, and refused.
     */
    #[Test]
    #[DataProvider('provideIndeterminateConditions')]
    public function itRefusesAConditionItDoesNotUnderstand(string $fixture): void
    {
        // Given
        $document = $this->document($fixture);
        $message = 'The Conditions hold a condition the package does not understand, and the assertion is Indeterminate (M-13).';

        // Then
        $this->expectException(IndeterminateCondition::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        ConditionsReader::read($this->child($document, 'Conditions'), $this->context());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideIndeterminateConditions(): iterable
    {
        yield 'a saml:Condition with an xsi:type' => ['hostile/assertion-condition-xsi-type-refused.xml'];
        yield 'an element of another namespace' => ['hostile/assertion-conditions-unknown-child-refused.xml'];
    }

    /**
     * §9.2 row 24, section 8, SAML Core §2.5.1.6: a saml:ProxyRestriction, with Count="0" and with an Audience.
     */
    #[Test]
    #[DataProvider('provideProxyRestrictions')]
    public function itRefusesAProxyRestriction(string $fixture): void
    {
        // Given
        $document = $this->document($fixture);
        $message = 'The Conditions hold a saml:ProxyRestriction, which the package does not support (section 8).';

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        ConditionsReader::read($this->child($document, 'Conditions'), $this->context());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideProxyRestrictions(): iterable
    {
        yield 'Count="0"' => ['hostile/assertion-proxy-restriction-count-zero-refused.xml'];
        yield 'with an Audience' => ['hostile/assertion-proxy-restriction-audience-refused.xml'];
    }

    /**
     * Section 7, M-17: eight AudienceRestriction, and sixteen Audience in one, the bounds, are accepted.
     */
    #[Test]
    #[DataProvider('provideCountsAtTheirBound')]
    public function itAcceptsACountAtItsBound(string $fixture, int $restrictions, int $audiences): void
    {
        // Given
        $conditions = $this->child($this->document($fixture), 'Conditions');

        // When
        $read = ConditionsReader::read($conditions, $this->context());

        // Then
        static::assertSame(
            array_fill(0, $restrictions, $audiences),
            array_map(count(...), $read->audiences),
        );
    }

    /**
     * @return iterable<string, array{string, int, int}>
     */
    public static function provideCountsAtTheirBound(): iterable
    {
        yield 'eight AudienceRestriction' => ['behaviour/assertion-eight-audience-restrictions-accepted.xml', 8, 1];
        yield 'sixteen Audience in a restriction' => ['behaviour/assertion-sixteen-audiences-accepted.xml', 1, 16];
    }

    /**
     * §9.2 row 36, section 7, M-17: nine AudienceRestriction; seventeen Audience in one; the message names the bound.
     */
    #[Test]
    #[DataProvider('provideCountsOverTheirBound')]
    public function itRefusesACountOverItsBound(string $fixture, string $message): void
    {
        // Given
        $document = $this->document($fixture);

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        ConditionsReader::read($this->child($document, 'Conditions'), $this->context());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideCountsOverTheirBound(): iterable
    {
        yield 'nine AudienceRestriction' => [
            'hostile/assertion-nine-audience-restrictions-refused.xml',
            'The Conditions hold more than 8 AudienceRestriction, the bound of section 7 (M-17).',
        ];
        yield 'seventeen Audience in a restriction' => [
            'hostile/assertion-seventeen-audiences-refused.xml',
            'An AudienceRestriction holds more than 16 Audience, the bound of section 7 (M-17).',
        ];
    }
}
