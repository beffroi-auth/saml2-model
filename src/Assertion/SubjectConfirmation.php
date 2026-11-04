<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Assertion;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Characters;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Saml2\Model\Value\Uri;
use DateTimeImmutable;

/**
 * SAML Core §2.4.1.2, SAML Profiles §4.1.4.2
 */
final readonly class SubjectConfirmation
{
    /**
     * @throws MalformedMessage
     */
    public function __construct(
        public string $recipient,
        public DateTimeImmutable $notOnOrAfter,
        public ?string $inResponseTo,
        public ?string $address,
    ) {
        Uri::read($recipient);
        if ($inResponseTo !== null) {
            SamlId::read($inResponseTo);
        }
        if ($address !== null && ! Characters::carriedByXml($address)) {
            throw new MalformedMessage('The Address holds a character XML does not carry, a NUL among them (M-15).');
        }
    }
}
