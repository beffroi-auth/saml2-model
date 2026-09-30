<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Assertion;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Uri;
use DateTimeImmutable;

/**
 * The one saml:AuthnStatement of an assertion (SAML Core §2.7.2, M-4): when the principal authenticated, the
 * SessionIndex the Single Logout profile names the session by, the SessionNotOnOrAfter that bounds the session the
 * consumer opens (SAML Profiles §4.1.4.3), and the AuthnContextClassRef, a URI of M-6. Whether the two times hold
 * against the clock is the rule of the reader (M-7).
 */
final readonly class AuthnStatement
{
    /**
     * @throws MalformedMessage when the authentication context class is not a URI of M-6
     */
    public function __construct(
        public DateTimeImmutable $authnInstant,
        public ?string $sessionIndex,
        public ?DateTimeImmutable $sessionNotOnOrAfter,
        public string $authnContextClassRef,
    ) {
        Uri::read($authnContextClassRef);
    }
}
