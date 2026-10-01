<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Assertion;

use Beffroi\Saml2\Model\Assertion\AuthnStatement;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3, M-6: the authentication statement, its context class a URI (SAML Core §2.7.2).
 */
final class AuthnStatementTest extends TestCase
{
    /**
     * Section 5.3: the instant, the session index, the end of the session and the context class, kept as given.
     */
    #[Test]
    public function itKeepsItsInstantSessionAndContextClass(): void
    {
        // Given
        $authnInstant = new DateTimeImmutable('2026-09-30T11:59:57Z');
        $sessionNotOnOrAfter = new DateTimeImmutable('2026-09-30T19:59:58Z');

        // When
        $statement = new AuthnStatement(
            $authnInstant,
            '_session',
            $sessionNotOnOrAfter,
            'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
        );

        // Then
        static::assertSame(
            [
                $authnInstant,
                '_session',
                $sessionNotOnOrAfter,
                'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            ],
            [
                $statement->authnInstant,
                $statement->sessionIndex,
                $statement->sessionNotOnOrAfter,
                $statement->authnContextClassRef,
            ],
        );
    }

    /**
     * M-6, section 6.1 step 10: the AuthnContextClassRef is a URI.
     */
    #[Test]
    public function itRefusesAContextClassThatIsNotAUri(): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A URI is not absolute (M-6).');

        // When
        new AuthnStatement(new DateTimeImmutable('2026-09-30T11:59:57Z'), null, null, 'Password');
    }

    /**
     * M-15: a session index holding a NUL, which the DOM would cut the written value at, refused whoever builds the
     * statement.
     */
    #[Test]
    public function itRefusesASessionIndexXmlDoesNotCarry(): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The SessionIndex holds a character XML does not carry, a NUL among them (M-15).');

        // When
        new AuthnStatement(
            new DateTimeImmutable('2026-09-30T11:59:57Z'),
            "_session\u{0}.other",
            null,
            'urn:oasis:names:tc:SAML:2.0:ac:classes:Password',
        );
    }
}
