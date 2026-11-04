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
 * SAML Core §3.2.2, SAML Profiles §4.1.4.2
 */
final readonly class Response
{
    /**
     * @throws MalformedMessage when a value is not of its lexical form, when a status of Success comes without an
     *                          assertion, or another with one (M-13)
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
