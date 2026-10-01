<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Assertion;

use Beffroi\Saml2\Model\Assertion\AuthnStatement;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Particle;
use Beffroi\Saml2\Model\Internal\Schema;
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
        Schema::children($statement, 'saml:AuthnStatement', [
            Particle::of(Schema::saml('SubjectLocality'), 0, 1),
            Particle::of(Schema::saml('AuthnContext'), 1, 1),
        ]);
        $authnInstant = Time::read(Schema::attribute($statement, 'saml:AuthnStatement', 'AuthnInstant'));
        if ($authnInstant > $context->window->latest()) {
            throw new OutsideValidityWindow('The AuthnInstant of the authentication statement is later than now plus the clock skew (M-7).');
        }
        $session = Attributes::optional($statement, new Name(null, 'SessionNotOnOrAfter'));
        $sessionNotOnOrAfter = $session === null ? null : Time::read($session);
        if ($sessionNotOnOrAfter instanceof DateTimeImmutable && $sessionNotOnOrAfter <= $context->window->earliest()) {
            throw new OutsideValidityWindow('The SessionNotOnOrAfter of the authentication statement is at or before now minus the clock skew (M-7).');
        }

        return new AuthnStatement(
            $authnInstant,
            Attributes::optional($statement, new Name(null, 'SessionIndex')),
            $sessionNotOnOrAfter,
            self::classRef(Children::one($statement, Schema::saml('AuthnContext'))),
        );
    }

    private static function classRef(Element $authnContext): string
    {
        Schema::unsupported(
            $authnContext,
            [Schema::saml('AuthnContextDecl'), Schema::saml('AuthnContextDeclRef')],
            'The authentication context is a saml:AuthnContextDecl or a saml:AuthnContextDeclRef, which the package does not support (section 8).',
        );
        Schema::children($authnContext, 'saml:AuthnContext', [
            Particle::of(Schema::saml('AuthnContextClassRef'), 1, 1),
            Particle::of(Schema::saml('AuthenticatingAuthority'), 0, Particle::UNBOUNDED),
        ]);

        return Text::of(Children::one($authnContext, Schema::saml('AuthnContextClassRef')));
    }
}
