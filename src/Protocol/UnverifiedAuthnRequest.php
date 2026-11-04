<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Assertion\IssuerReader;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;

/**
 * Its Issuer only chooses the service provider whose metadata verifies it: AuthnRequestValidator reads it again from
 * what was verified or authenticated (M-1).
 */
final readonly class UnverifiedAuthnRequest
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
        $root = $document->root();
        if (! new Name(Saml::PROTOCOL, 'AuthnRequest')->matches($root)) {
            throw new MalformedMessage('The root of the document is not a samlp:AuthnRequest (section 6.2).');
        }

        return new self($document, IssuerReader::unverified($root, 'samlp:AuthnRequest'));
    }
}
