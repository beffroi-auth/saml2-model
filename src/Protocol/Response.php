<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

use Beffroi\Saml2\Model\Assertion\Assertion;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Saml2\Model\Value\Uri;
use DateTimeImmutable;

/**
 * A samlp:Response of the Web Browser SSO profile (section 5.3, SAML Core §3.2.2, SAML Profiles §4.1.4.2), whoever
 * builds it: its ID and InResponseTo IDs of M-6, the request it answers or none for an unsolicited response (M-10); its
 * Destination a URI of M-6, absent when the response is not signed; its Issuer, which the package always writes; its
 * status; and its one assertion when the status is Success, none otherwise (M-13). The writer of the identity provider
 * builds one (story #9); the service provider reads an AcceptedAssertion instead (section 5.5).
 */
final readonly class Response
{
    /**
     * @throws MalformedMessage when the ID or the InResponseTo is not an ID, or the Destination not a URI, of M-6; when
     *                          a status of Success comes without an assertion, or another with one (M-13)
     */
    public function __construct(
        public string $id,
        public DateTimeImmutable $issueInstant,
        public Issuer $issuer,
        public ?string $destination,
        public ?string $inResponseTo,
        public Status $status,
        public ?Assertion $assertion,
    ) {
        SamlId::read($id);
        if ($destination !== null) {
            Uri::read($destination);
        }
        if ($inResponseTo !== null) {
            SamlId::read($inResponseTo);
        }
        if ($status->code === StatusCode::Success && ! $assertion instanceof Assertion) {
            throw new MalformedMessage('A response whose status is Success carries an assertion (M-13).');
        }
        if ($status->code !== StatusCode::Success && $assertion instanceof Assertion) {
            throw new MalformedMessage('A response whose status is not Success carries no assertion (M-13).');
        }
    }
}
