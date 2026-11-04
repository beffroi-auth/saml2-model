<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Saml2\Model\Value\Uri;
use DateTimeImmutable;

/**
 * SAML Core §3.7.2
 *
 * The Destination is required, as in a logout request, and so is the InResponseTo: a logout response answers the
 * request the consumer names (M-10).
 */
final readonly class LogoutResponse
{
    /**
     * @throws MalformedMessage
     */
    public function __construct(
        public string $id,
        public DateTimeImmutable $issueInstant,
        public Issuer $issuer,
        public string $destination,
        public string $inResponseTo,
        public Status $status,
    ) {
        SamlId::read($id);
        Uri::read($destination);
        SamlId::read($inResponseTo);
    }
}
