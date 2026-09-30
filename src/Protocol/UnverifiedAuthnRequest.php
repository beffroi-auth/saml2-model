<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\Value\Uri;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\ForeignNode;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use function count;

/**
 * An AuthnRequest as it arrived, before anything is verified (section 5.4, M-1): the root checked to be
 * samlp:AuthnRequest, and its Issuer read and nothing else, what the identity provider needs to choose the service
 * provider whose metadata verifies it. AuthnRequestValidator reads the Issuer again from what was verified or
 * authenticated, and compares it with that service provider's entity ID (M-8).
 */
final readonly class UnverifiedAuthnRequest
{
    private function __construct(
        public Document $document,
        public ?string $issuer,
    ) {
    }

    /**
     * @throws MalformedMessage when the root is another element, holds more than one saml:Issuer (M-4), or its Issuer
     *                          is not a URI of M-6
     * @throws MixedContent when the Issuer holds an element
     * @throws ForeignNode when the document is not one Core loaded
     */
    public static function of(Document $document): self
    {
        $root = $document->root();
        if (! new Name(Saml::PROTOCOL, 'AuthnRequest')->matches($root)) {
            throw new MalformedMessage('The root of the document is not a samlp:AuthnRequest (section 6.2).');
        }
        $issuers = Children::named($root, new Name(Saml::ASSERTION, 'Issuer'));
        if (count($issuers) > 1) {
            throw new MalformedMessage('The samlp:AuthnRequest holds more than one saml:Issuer (M-4).');
        }

        return new self($document, $issuers === [] ? null : Uri::read(Text::of($issuers[0])));
    }
}
