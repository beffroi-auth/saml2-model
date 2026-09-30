<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Saml2\Model\Value\Uri;
use DateTimeImmutable;

/**
 * A samlp:LogoutResponse (section 5.3, SAML Core §3.7.2): its ID, its IssueInstant, its Issuer, its Destination, the
 * ID of the LogoutRequest it answers, and its status, whichever it is: a partial logout is an answer (section 6.4).
 * The Destination is required, as in a logout request (section 6.3), and so is the InResponseTo, since a logout
 * response answers the request the consumer names (M-10). Whoever builds it, the two IDs are IDs of M-6 and the
 * Destination a URI of M-6.
 */
final readonly class LogoutResponse
{
    /**
     * @throws MalformedMessage when the ID, the InResponseTo or the Destination is not of its lexical form (M-6)
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
