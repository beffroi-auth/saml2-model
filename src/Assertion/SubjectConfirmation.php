<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Assertion;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Characters;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Saml2\Model\Value\Uri;
use DateTimeImmutable;

/**
 * The one saml:SubjectConfirmation of an assertion, of method bearer, the only one the package supports (M-4, section
 * 8), and what its SubjectConfirmationData holds (SAML Core §2.4.1.2, SAML Profiles §4.1.4.2): the Recipient, a URI
 * of M-6; the NotOnOrAfter that ends the bearer window; the InResponseTo, an ID of M-6, absent for an unsolicited
 * response (M-10); the Address, kept as read and never checked but for the characters XML carries, whoever builds it
 * (M-15). Whether the Recipient is the URL of arrival and the window holds against the clock are the rules of the
 * reader (M-7, M-8).
 */
final readonly class SubjectConfirmation
{
    /**
     * @throws MalformedMessage when the recipient is not a URI, or the InResponseTo not an ID, of M-6, or the address
     *                          holds a character XML does not carry (M-15)
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
