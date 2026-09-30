<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Assertion;

use Beffroi\Saml2\Model\Assertion\AuthnStatement;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use DateTimeImmutable;
use Dom\Element;

/**
 * The authentication statement of an assertion, section 6.1 step 10: an AuthnInstant not later than now plus the skew,
 * a SessionNotOnOrAfter in the window of M-7 when present, the SessionIndex as read, saml:SubjectLocality accepted and
 * not read, and an AuthnContext holding one AuthnContextClassRef, its saml:AuthenticatingAuthority elements accepted
 * and not read; saml:AuthnContextDecl and saml:AuthnContextDeclRef are refused by name (section 8).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class AuthnStatementReader
{
    /**
     * @throws MalformedMessage when an element is missing, repeated, out of order or not allowed, or a value is not of
     *                          its lexical form (M-4, M-5, M-6)
     * @throws OutsideValidityWindow when the AuthnInstant is ahead, or the session has ended (M-7)
     * @throws Unsupported when the authentication context is a declaration (section 8)
     */
    public static function read(Element $statement, AssertionContext $context): AuthnStatement
    {
        Structure::sequence(
            $statement,
            [
                Particle::optional(Structure::saml('SubjectLocality'), 'saml:SubjectLocality'),
                Particle::one(Structure::saml('AuthnContext'), 'saml:AuthnContext'),
            ],
            'saml:AuthnStatement',
        );
        $authnInstant = Time::read(Structure::attribute(
            $statement,
            'AuthnInstant',
            'The saml:AuthnStatement has no AuthnInstant (M-5).',
        ));
        if ($authnInstant > $context->latest()) {
            throw new OutsideValidityWindow('The AuthnInstant of the authentication statement is later than now plus the clock skew (M-7).');
        }
        $session = Attributes::optional($statement, new Name(null, 'SessionNotOnOrAfter'));
        $sessionNotOnOrAfter = $session === null ? null : Time::read($session);
        if ($sessionNotOnOrAfter instanceof DateTimeImmutable && $sessionNotOnOrAfter <= $context->earliest()) {
            throw new OutsideValidityWindow('The SessionNotOnOrAfter of the authentication statement is at or before now minus the clock skew (M-7).');
        }

        return new AuthnStatement(
            $authnInstant,
            Attributes::optional($statement, new Name(null, 'SessionIndex')),
            $sessionNotOnOrAfter,
            self::classRef(Children::one($statement, Structure::saml('AuthnContext'))),
        );
    }

    private static function classRef(Element $authnContext): string
    {
        Structure::unsupported(
            $authnContext,
            [Structure::saml('AuthnContextDecl'), Structure::saml('AuthnContextDeclRef')],
            'The authentication context is a saml:AuthnContextDecl or a saml:AuthnContextDeclRef, which the package does not support (section 8).',
        );
        Structure::sequence(
            $authnContext,
            [
                Particle::one(Structure::saml('AuthnContextClassRef'), 'saml:AuthnContextClassRef'),
                Particle::any([Structure::saml('AuthenticatingAuthority')]),
            ],
            'saml:AuthnContext',
        );

        return Text::of(Children::one($authnContext, Structure::saml('AuthnContextClassRef')));
    }
}
