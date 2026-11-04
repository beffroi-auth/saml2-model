<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Assertion\IssuerReader;
use Beffroi\Saml2\Model\Internal\Logout\Envelope;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\MixedContent;

/**
 * Its Issuer only chooses the peer whose keys verify it: LogoutRequestValidator reads it again from what was verified
 * or authenticated (M-1).
 */
final readonly class UnverifiedLogoutRequest
{
    private function __construct(
        public Document $document,
        public ?string $issuer,
    ) {
    }

    /**
     * @throws MalformedMessage
     * @throws MixedContent
     */
    public static function of(Document $document): self
    {
        $root = Envelope::root($document, 'LogoutRequest');

        return new self($document, IssuerReader::unverified($root, 'samlp:LogoutRequest'));
    }
}
