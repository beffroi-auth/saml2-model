<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Assertion\IssuerReader;
use Beffroi\Saml2\Model\Internal\Logout\Envelope;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;

/**
 * Its Issuer and its InResponseTo only choose the peer and the request: LogoutResponseValidator reads both again from
 * what was verified or authenticated (M-1).
 */
final readonly class UnverifiedLogoutResponse
{
    private function __construct(
        public Document $document,
        public ?string $issuer,
        public ?string $inResponseTo,
    ) {
    }

    /**
     * @throws MalformedMessage
     * @throws MixedContent
     */
    public static function of(Document $document): self
    {
        $root = Envelope::root($document, 'LogoutResponse');
        $inResponseTo = Attributes::optional($root, new Name(null, 'InResponseTo'));

        return new self(
            $document,
            IssuerReader::unverified($root, 'samlp:LogoutResponse'),
            $inResponseTo === null ? null : SamlId::read($inResponseTo),
        );
    }
}
