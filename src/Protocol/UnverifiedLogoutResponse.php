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
 * A received samlp:LogoutResponse before any verification (section 5.4, M-1): the root checked, its Issuer and its
 * InResponseTo read and nothing else, what the consumer needs to choose the peer whose keys verify it and the request
 * it answers. Both are read again from what was verified or what the binding authenticated, and compared, by
 * LogoutResponseValidator.
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
     * @throws MalformedMessage when the root is another element, or holds more than one saml:Issuer, or the Issuer is
     *                          not a URI of M-6, or the InResponseTo not an ID of M-6
     * @throws MixedContent when the Issuer holds an element
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
