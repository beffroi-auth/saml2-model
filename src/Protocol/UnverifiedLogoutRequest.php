<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Logout\Envelope;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\MixedContent;

/**
 * A received samlp:LogoutRequest before any verification (section 5.4, M-1): the root checked, its Issuer read and
 * nothing else, what the consumer needs to choose the peer whose keys verify it. The Issuer is read again from what was
 * verified or what the binding authenticated, and compared, by LogoutRequestValidator.
 */
final readonly class UnverifiedLogoutRequest
{
    private function __construct(
        public Document $document,
        public ?string $issuer,
    ) {
    }

    /**
     * @throws MalformedMessage when the root is another element, or holds more than one saml:Issuer, or the Issuer is
     *                          not a URI of M-6
     * @throws MixedContent when the Issuer holds an element
     */
    public static function of(Document $document): self
    {
        $root = Envelope::root($document, 'LogoutRequest');

        return new self($document, Envelope::unverifiedIssuer($root));
    }
}
