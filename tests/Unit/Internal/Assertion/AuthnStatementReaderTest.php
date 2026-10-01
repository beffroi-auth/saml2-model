<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Assertion\AuthnStatementReader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.1 step 10, M-7: the authentication statement of an assertion, its instant, its session and its context
 * class (SAML Core §2.7.2).
 */
final class AuthnStatementReaderTest extends TestCase
{
    use AssertionFixtures;

    /**
     * Section 5.3: the AuthnInstant, the SessionIndex, the SessionNotOnOrAfter and the AuthnContextClassRef, as read.
     */
    #[Test]
    public function itReadsTheInstantSessionAndContextClass(): void
    {
        // Given
        $statement = $this->child($this->document('behaviour/assertion-valid-accepted.xml'), 'AuthnStatement');

        // When
        $read = AuthnStatementReader::read($statement, $this->context());

        // Then
        static::assertSame(
            [
                '2026-09-30T11:59:57Z',
                '_session',
                '2026-09-30T19:59:58Z',
                'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            ],
            [
                $read->authnInstant->format('Y-m-d\TH:i:s\Z'),
                $read->sessionIndex,
                $read->sessionNotOnOrAfter?->format('Y-m-d\TH:i:s\Z'),
                $read->authnContextClassRef,
            ],
        );
    }

    /**
     * SAML Core §2.7.2: SessionIndex and SessionNotOnOrAfter are optional.
     */
    #[Test]
    public function itReadsAStatementWithoutSession(): void
    {
        // Given
        $statement = $this->child(
            $this->document('behaviour/assertion-authn-statement-without-session-accepted.xml'),
            'AuthnStatement',
        );

        // When
        $read = AuthnStatementReader::read($statement, $this->context());

        // Then
        static::assertSame([null, null], [$read->sessionIndex, $read->sessionNotOnOrAfter]);
    }

    /**
     * §9.3 row 19, section 6.1 step 10: a saml:SubjectLocality and two saml:AuthenticatingAuthority are accepted and
     * not read.
     */
    #[Test]
    public function itAcceptsASubjectLocalityAndAuthenticatingAuthorities(): void
    {
        // Given
        $statement = $this->child(
            $this->document('behaviour/assertion-subject-locality-and-authenticating-authorities-accepted.xml'),
            'AuthnStatement',
        );

        // When
        $read = AuthnStatementReader::read($statement, $this->context());

        // Then
        static::assertSame(
            'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            $read->authnContextClassRef,
        );
    }

    /**
     * M-7: an AuthnInstant at now plus the skew, and a SessionNotOnOrAfter one second after now minus the skew, the
     * edges of their windows, are accepted.
     */
    #[Test]
    #[DataProvider('provideWindowEdges')]
    public function itAcceptsTheEdgesOfItsWindows(
        string $fixture,
        string $authnInstant,
        string $sessionNotOnOrAfter,
    ): void {
        // Given
        $statement = $this->child($this->document($fixture), 'AuthnStatement');

        // When
        $read = AuthnStatementReader::read($statement, $this->context());

        // Then
        static::assertSame(
            [$authnInstant, $sessionNotOnOrAfter],
            [$read->authnInstant->format('Y-m-d\TH:i:s\Z'), $read->sessionNotOnOrAfter?->format('Y-m-d\TH:i:s\Z')],
        );
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideWindowEdges(): iterable
    {
        yield 'AuthnInstant at now plus the skew' => [
            'behaviour/assertion-authn-instant-at-skew-accepted.xml',
            '2026-09-30T12:03:00Z',
            '2026-09-30T19:59:58Z',
        ];
        yield 'SessionNotOnOrAfter a second after now minus the skew' => [
            'behaviour/assertion-session-not-on-or-after-after-skew-accepted.xml',
            '2026-09-30T11:59:57Z',
            '2026-09-30T11:57:01Z',
        ];
    }

    /**
     * §9.2 row 18, M-7: the AuthnInstant one second beyond now plus the skew; the SessionNotOnOrAfter passed, at now
     * minus the skew; each message names its window.
     */
    #[Test]
    #[DataProvider('provideWindowsOutside')]
    public function itRefusesATimeOutsideItsWindow(string $fixture, string $message): void
    {
        // Given
        $document = $this->document($fixture);

        // Then
        $this->expectException(OutsideValidityWindow::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        AuthnStatementReader::read($this->child($document, 'AuthnStatement'), $this->context());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideWindowsOutside(): iterable
    {
        yield 'AuthnInstant a second beyond now plus the skew' => [
            'hostile/assertion-authn-instant-beyond-skew-refused.xml',
            'The AuthnInstant of the authentication statement is later than now plus the clock skew (M-7).',
        ];
        yield 'SessionNotOnOrAfter passed, at now minus the skew' => [
            'hostile/assertion-session-not-on-or-after-passed-refused.xml',
            'The SessionNotOnOrAfter of the authentication statement is at or before now minus the clock skew (M-7).',
        ];
    }

    /**
     * M-4, M-5, section 6.1 step 10: an AuthnContext without AuthnContextClassRef; an AuthnStatement without
     * AuthnContext.
     */
    #[Test]
    #[DataProvider('provideMalformedStatements')]
    public function itRefusesAMalformedStatement(string $fixture, string $message): void
    {
        // Given
        $document = $this->document($fixture);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        AuthnStatementReader::read($this->child($document, 'AuthnStatement'), $this->context());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMalformedStatements(): iterable
    {
        yield 'an AuthnContext without AuthnContextClassRef' => [
            'hostile/assertion-authn-context-without-class-ref-refused.xml',
            'The saml:AuthnContext holds no saml:AuthnContextClassRef (M-4).',
        ];
        yield 'an AuthnStatement without AuthnContext' => [
            'hostile/assertion-authn-statement-without-authn-context-refused.xml',
            'The saml:AuthnStatement holds no saml:AuthnContext (M-4).',
        ];
    }

    /**
     * Section 8, section 6.1 step 10: saml:AuthnContextDecl next to the class, saml:AuthnContextDeclRef in its place.
     */
    #[Test]
    #[DataProvider('provideDeclarations')]
    public function itRefusesADeclarationOfTheContext(string $fixture): void
    {
        // Given
        $document = $this->document($fixture);
        $message = 'The authentication context is a saml:AuthnContextDecl or a saml:AuthnContextDeclRef, which the package does not support (section 8).';

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        AuthnStatementReader::read($this->child($document, 'AuthnStatement'), $this->context());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDeclarations(): iterable
    {
        yield 'saml:AuthnContextDecl' => ['hostile/assertion-authn-context-decl-refused.xml'];
        yield 'saml:AuthnContextDeclRef' => ['hostile/assertion-authn-context-decl-ref-refused.xml'];
    }
}
