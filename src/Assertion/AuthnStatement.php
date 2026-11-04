<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Assertion;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Characters;
use Beffroi\Saml2\Model\Value\Uri;
use DateTimeImmutable;

/**
 * SAML Core §2.7.2
 */
final readonly class AuthnStatement
{
    /**
     * @throws MalformedMessage
     */
    public function __construct(
        public DateTimeImmutable $authnInstant,
        public ?string $sessionIndex,
        public ?DateTimeImmutable $sessionNotOnOrAfter,
        public string $authnContextClassRef,
    ) {
        Uri::read($authnContextClassRef);
        if ($sessionIndex !== null && ! Characters::carriedByXml($sessionIndex)) {
            throw new MalformedMessage('The SessionIndex holds a character XML does not carry, a NUL among them (M-15).');
        }
    }
}
