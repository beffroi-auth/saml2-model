<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Assertion\HeaderReader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.1 step 7: the header of an assertion, its Version, ID, IssueInstant and Issuer (SAML Core §2.3.3), and
 * saml:Advice refused by name (section 8).
 */
final class HeaderReaderTest extends TestCase
{
    use AssertionFixtures;

    /**
     * Section 6.1 step 7: the ID, the IssueInstant and the Issuer, as read.
     */
    #[Test]
    public function itReadsTheIdIssueInstantAndIssuer(): void
    {
        // Given
        $document = $this->document('behaviour/assertion-valid-accepted.xml');

        // When
        [$id, $issueInstant, $issuer] = HeaderReader::read($document->root(), $this->context());

        // Then
        static::assertSame(
            ['_assertion', '2026-09-30T11:59:58Z', 'https://idp.example.com/saml'],
            [$id, $issueInstant->format('Y-m-d\TH:i:s\Z'), $issuer->entityId],
        );
    }

    /**
     * M-7: an IssueInstant at now plus the skew, the edge of its window, is accepted.
     */
    #[Test]
    public function itAcceptsAnIssueInstantAtNowPlusTheSkew(): void
    {
        // Given
        $document = $this->document('behaviour/assertion-issue-instant-at-skew-accepted.xml');

        // When
        [, $issueInstant] = HeaderReader::read($document->root(), $this->context());

        // Then
        static::assertSame('2026-09-30T12:03:00Z', $issueInstant->format('Y-m-d\TH:i:s\Z'));
    }

    /**
     * §9.2 row 18, M-7: an IssueInstant one second beyond now plus the skew; the message names the window.
     */
    #[Test]
    public function itRefusesAnIssueInstantBeyondNowPlusTheSkew(): void
    {
        // Given
        $document = $this->document('hostile/assertion-issue-instant-beyond-skew-refused.xml');
        $message = 'The IssueInstant of the assertion is later than now plus the clock skew (M-7).';

        // Then
        $this->expectException(OutsideValidityWindow::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        HeaderReader::read($document->root(), $this->context());
    }

    /**
     * M-7: an assertion exactly maxMessageAge old, the edge of its window, the skew not added, is accepted.
     */
    #[Test]
    public function itAcceptsAnAssertionExactlyMaxMessageAgeOld(): void
    {
        // Given
        $document = $this->document('behaviour/assertion-issue-instant-max-message-age-ago-accepted.xml');

        // When
        [, $issueInstant] = HeaderReader::read($document->root(), $this->context());

        // Then
        static::assertSame('2026-09-30T11:55:00Z', $issueInstant->format('Y-m-d\TH:i:s\Z'));
    }

    /**
     * §9.2 row 18, M-7: an assertion one second older than maxMessageAge, which a fresh response may carry, is a replay
     * the bearer window does not see.
     */
    #[Test]
    public function itRefusesAnAssertionOlderThanMaxMessageAge(): void
    {
        // Given
        $document = $this->document('hostile/assertion-issue-instant-older-than-max-message-age-refused.xml');
        $message = 'The IssueInstant of the assertion is older than maxMessageAge (M-7).';

        // Then
        $this->expectException(OutsideValidityWindow::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        HeaderReader::read($document->root(), $this->context());
    }

    /**
     * §9.2 row 26, M-6: Version="2.1".
     */
    #[Test]
    public function itRefusesAVersionOtherThan20(): void
    {
        // Given
        $document = $this->document('hostile/assertion-version-2-1-refused.xml');
        $message = 'The version is not 2.0 (M-6).';

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        HeaderReader::read($document->root(), $this->context());
    }

    /**
     * M-5, SAML Core §2.3.3: Version, ID and IssueInstant are required.
     */
    #[Test]
    #[DataProvider('provideMissingAttributes')]
    public function itRefusesAMissingAttribute(string $fixture, string $message): void
    {
        // Given
        $document = $this->document($fixture);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        HeaderReader::read($document->root(), $this->context());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMissingAttributes(): iterable
    {
        yield 'Version' => [
            'hostile/assertion-without-version-refused.xml',
            'The saml:Assertion has no Version (M-5).',
        ];
        yield 'ID' => ['hostile/assertion-without-id-refused.xml', 'The saml:Assertion has no ID (M-5).'];
        yield 'IssueInstant' => [
            'hostile/assertion-without-issue-instant-refused.xml',
            'The saml:Assertion has no IssueInstant (M-5).',
        ];
    }

    /**
     * §9.2 row 7, section 8: an assertion inside the saml:Advice of the verified assertion; the Advice is refused by
     * name, whatever it holds.
     */
    #[Test]
    public function itRefusesAdvice(): void
    {
        // Given
        $document = $this->document('hostile/assertion-advice-refused.xml');
        $message = 'The assertion holds a saml:Advice, which the package does not support (section 8).';

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        HeaderReader::read($document->root(), $this->context());
    }
}
