<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion;

use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\InResponseToMismatch;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Exception\RecipientMismatch;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Assertion\SubjectReader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.1 step 8, M-4, M-12: the subject of an assertion, one NameID and one bearer confirmation (SAML Core
 * §2.4.1, SAML Profiles §4.1.4.2).
 */
final class SubjectReaderTest extends TestCase
{
    use AssertionFixtures;

    /**
     * M-12, section 5.3: the NameID, its format and its qualifiers, as read.
     */
    #[Test]
    public function itReadsTheNameId(): void
    {
        // Given
        $subject = $this->child($this->document('behaviour/assertion-valid-accepted.xml'), 'Subject');

        // When
        [$nameId] = SubjectReader::read($subject, $this->context());

        // Then
        static::assertSame(
            [
                '_7a2f4c1d9e',
                NameIdFormat::Persistent,
                'https://idp.example.com/saml',
                'https://sp.example.com/saml',
                null,
            ],
            [$nameId->value, $nameId->format, $nameId->nameQualifier, $nameId->spNameQualifier, $nameId->spProvidedId],
        );
    }

    /**
     * §9.3 row 1, M-12, I-12: a comment splits the NameID; its value is the text of both sides, as the signer signed
     * it, never the text before the comment.
     */
    #[Test]
    public function itReadsACommentSplitNameIdWhole(): void
    {
        // Given
        $subject = $this->child($this->document('behaviour/assertion-name-id-comment-split-accepted.xml'), 'Subject');

        // When
        [$nameId] = SubjectReader::read($subject, $this->context());

        // Then
        static::assertSame('user@example.com.evil.com', $nameId->value);
    }

    /**
     * Section 6.1 step 8, section 5.3: the Recipient, the NotOnOrAfter, the InResponseTo and the Address of the bearer
     * confirmation, as read.
     */
    #[Test]
    public function itReadsTheBearerConfirmation(): void
    {
        // Given
        $subject = $this->child($this->document('behaviour/assertion-valid-accepted.xml'), 'Subject');

        // When
        [, $confirmation] = SubjectReader::read($subject, $this->context());

        // Then
        static::assertSame(
            ['https://sp.example.com/saml/acs', '2026-09-30T12:04:58Z', '_request', '192.0.2.1'],
            [
                $confirmation->recipient,
                $confirmation->notOnOrAfter->format('Y-m-d\TH:i:s\Z'),
                $confirmation->inResponseTo,
                $confirmation->address,
            ],
        );
    }

    /**
     * M-10, SAML Profiles §4.1.5: an unsolicited response's confirmation answers no request.
     */
    #[Test]
    public function itAcceptsAConfirmationWithoutInResponseToForAnUnsolicitedResponse(): void
    {
        // Given
        $subject = $this->child($this->document('behaviour/assertion-unsolicited-accepted.xml'), 'Subject');

        // When
        [, $confirmation] = SubjectReader::read($subject, $this->context(null));

        // Then
        static::assertSame([null, null], [$confirmation->inResponseTo, $confirmation->address]);
    }

    /**
     * M-7: a bearer NotOnOrAfter one second after now minus the skew, and one at now plus maxBearerWindow, the edges
     * of the bearer window, are accepted.
     */
    #[Test]
    #[DataProvider('provideBearerWindowEdges')]
    public function itAcceptsABearerNotOnOrAfterAtTheEdgesOfItsWindow(string $fixture, string $notOnOrAfter): void
    {
        // Given
        $subject = $this->child($this->document($fixture), 'Subject');

        // When
        [, $confirmation] = SubjectReader::read($subject, $this->context());

        // Then
        static::assertSame($notOnOrAfter, $confirmation->notOnOrAfter->format('Y-m-d\TH:i:s\Z'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideBearerWindowEdges(): iterable
    {
        yield 'a second after now minus the skew' => [
            'behaviour/assertion-bearer-not-on-or-after-after-skew-accepted.xml',
            '2026-09-30T11:57:01Z',
        ];
        yield 'now plus maxBearerWindow' => [
            'behaviour/assertion-bearer-window-at-bound-accepted.xml',
            '2026-09-30T13:00:00Z',
        ];
    }

    /**
     * §9.2 row 18, M-7: the bearer NotOnOrAfter passed, at now minus the skew; a bearer window beyond maxBearerWindow
     * by one second; each message names its window.
     */
    #[Test]
    #[DataProvider('provideBearerWindowsOutside')]
    public function itRefusesABearerNotOnOrAfterOutsideItsWindow(string $fixture, string $message): void
    {
        // Given
        $document = $this->document($fixture);

        // Then
        $this->expectException(OutsideValidityWindow::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        SubjectReader::read($this->child($document, 'Subject'), $this->context());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideBearerWindowsOutside(): iterable
    {
        yield 'passed, at now minus the skew' => [
            'hostile/assertion-bearer-not-on-or-after-passed-refused.xml',
            'The NotOnOrAfter of the bearer confirmation is at or before now minus the clock skew (M-7).',
        ];
        yield 'a second beyond now plus maxBearerWindow' => [
            'hostile/assertion-bearer-window-beyond-refused.xml',
            'The NotOnOrAfter of the bearer confirmation is later than now plus maxBearerWindow (M-7).',
        ];
    }

    /**
     * §9.2 row 14, M-8: a Recipient other than the URL of arrival, here by a trailing slash, compared exactly.
     */
    #[Test]
    public function itRefusesARecipientOtherThanTheUrlOfArrival(): void
    {
        // Given
        $document = $this->document('hostile/assertion-recipient-another-url-refused.xml');
        $message = 'The Recipient of the bearer confirmation is not the URL at which the response arrived (M-8).';

        // Then
        $this->expectException(RecipientMismatch::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        SubjectReader::read($this->child($document, 'Subject'), $this->context());
    }

    /**
     * §9.2 row 17, M-10: the InResponseTo of the confirmation another request; present on an unsolicited response;
     * absent on a solicited one.
     */
    #[Test]
    #[DataProvider('provideInResponseToMismatches')]
    public function itRefusesAnInResponseToOtherThanTheOneExpected(string $fixture, ?string $inResponseTo): void
    {
        // Given
        $document = $this->document($fixture);
        $message = 'The InResponseTo of the bearer confirmation is not the one the consumer expects (M-10).';

        // Then
        $this->expectException(InResponseToMismatch::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        SubjectReader::read($this->child($document, 'Subject'), $this->context($inResponseTo));
    }

    /**
     * @return iterable<string, array{string, ?string}>
     */
    public static function provideInResponseToMismatches(): iterable
    {
        yield 'another request' => ['hostile/assertion-in-response-to-another-request-refused.xml', '_request'];
        yield 'present on an unsolicited response' => ['behaviour/assertion-valid-accepted.xml', null];
        yield 'absent on a solicited response' => ['behaviour/assertion-unsolicited-accepted.xml', '_request'];
    }

    /**
     * §9.2 rows 14, 20, 25 and 28, M-4, M-5, SAML Profiles §4.1.4.2: the structure of the subject and of its bearer
     * confirmation; the Recipient absent; a SubjectConfirmationData with NotBefore, or without NotOnOrAfter; an
     * unknown saml: element in the subject; two bearer confirmations.
     */
    #[Test]
    #[DataProvider('provideMalformedSubjects')]
    public function itRefusesAMalformedSubject(string $fixture, string $message): void
    {
        // Given
        $document = $this->document($fixture);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        SubjectReader::read($this->child($document, 'Subject'), $this->context());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMalformedSubjects(): iterable
    {
        yield 'no NameID' => [
            'hostile/assertion-subject-without-name-id-refused.xml',
            'The saml:Subject holds no saml:NameID (M-4).',
        ];
        yield 'two NameID' => [
            'hostile/assertion-subject-two-name-ids-refused.xml',
            'The saml:Subject holds more than one saml:NameID (M-4).',
        ];
        yield 'an unknown saml: element in the subject' => [
            'hostile/assertion-subject-unknown-saml-element-refused.xml',
            'The saml:Subject holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
        yield 'the confirmation before the NameID' => [
            'hostile/assertion-subject-confirmation-before-name-id-refused.xml',
            'The saml:Subject holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
        yield 'no confirmation' => [
            'hostile/assertion-subject-without-confirmation-refused.xml',
            'The saml:Subject holds no saml:SubjectConfirmation (M-4).',
        ];
        yield 'two bearer confirmations' => [
            'hostile/assertion-two-bearer-confirmations-refused.xml',
            'The saml:Subject holds more than one saml:SubjectConfirmation (M-4).',
        ];
        yield 'a confirmation without Method' => [
            'hostile/assertion-confirmation-without-method-refused.xml',
            'The saml:SubjectConfirmation has no Method (M-5).',
        ];
        yield 'a confirmation without SubjectConfirmationData' => [
            'hostile/assertion-confirmation-without-data-refused.xml',
            'The saml:SubjectConfirmation holds no saml:SubjectConfirmationData (M-4).',
        ];
        yield 'a SubjectConfirmationData with NotBefore' => [
            'hostile/assertion-confirmation-data-not-before-refused.xml',
            'The bearer confirmation has a NotBefore (section 6.1).',
        ];
        yield 'a SubjectConfirmationData without NotOnOrAfter' => [
            'hostile/assertion-confirmation-data-without-not-on-or-after-refused.xml',
            'The bearer confirmation has no NotOnOrAfter (section 6.1).',
        ];
        yield 'the Recipient absent' => [
            'hostile/assertion-without-recipient-refused.xml',
            'The bearer confirmation has no Recipient (M-8).',
        ];
    }

    /**
     * §9.2 rows 28 and 29, section 8, section 6.7: a subject or a confirmation the package does not support; a
     * holder-of-key confirmation, a sender-vouches one; an identifier in the bearer confirmation, an element in its
     * SubjectConfirmationData; saml:BaseID, and saml:EncryptedID until sub-spike 9e.
     */
    #[Test]
    #[DataProvider('provideUnsupportedSubjects')]
    public function itRefusesASubjectThePackageDoesNotSupport(string $fixture, string $message): void
    {
        // Given
        $document = $this->document($fixture);

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        SubjectReader::read($this->child($document, 'Subject'), $this->context());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideUnsupportedSubjects(): iterable
    {
        yield 'a holder-of-key confirmation' => [
            'hostile/assertion-confirmation-holder-of-key-refused.xml',
            'The confirmation method is not bearer, the one the package supports (section 8).',
        ];
        yield 'a sender-vouches confirmation' => [
            'hostile/assertion-confirmation-sender-vouches-refused.xml',
            'The confirmation method is not bearer, the one the package supports (section 8).',
        ];
        yield 'a NameID in the bearer confirmation' => [
            'hostile/assertion-confirmation-name-id-refused.xml',
            'The bearer confirmation holds an identifier of its own, which the package does not support (section 8).',
        ];
        yield 'an element in the SubjectConfirmationData' => [
            'hostile/assertion-confirmation-data-element-refused.xml',
            'The SubjectConfirmationData of the bearer confirmation holds an element, which the package does not support (section 8).',
        ];
        yield 'saml:BaseID' => [
            'hostile/assertion-subject-base-id-refused.xml',
            'The subject is a saml:BaseID, which the package does not support (section 8).',
        ];
        yield 'saml:EncryptedID' => [
            'hostile/assertion-subject-encrypted-id-refused.xml',
            'The subject is a saml:EncryptedID, which the package does not support until sub-spike 9e (section 6.7).',
        ];
    }
}
