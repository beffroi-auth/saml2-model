<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Assertion\IssuerReader;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use function count;
use Dom\Element;

/**
 * Its Issuer and its InResponseTo only choose the identity provider: ResponseValidator reads both again from what was
 * verified (M-1).
 */
final readonly class UnverifiedResponse
{
    private function __construct(
        public Document $document,
        public ?string $issuer,
        public ?string $inResponseTo,
    ) {
    }

    /**
     * Two Issuers where one is read are refused rather than one of them picked (M-4).
     *
     * @throws MalformedMessage
     * @throws MixedContent
     */
    public static function of(Document $document): self
    {
        $root = $document->root();
        if (! new Name(Saml::PROTOCOL, 'Response')->matches($root)) {
            throw new MalformedMessage('The root of the document is not a samlp:Response (M-1).');
        }
        $inResponseTo = Attributes::optional($root, new Name(null, 'InResponseTo'));

        return new self($document, self::issuer($root), $inResponseTo === null ? null : SamlId::read($inResponseTo));
    }

    /**
     * @throws MalformedMessage
     * @throws MixedContent
     */
    private static function issuer(Element $response): ?string
    {
        $issuer = IssuerReader::unverified($response, 'samlp:Response');
        if ($issuer !== null) {
            return $issuer;
        }
        $assertions = Children::named($response, new Name(Saml::ASSERTION, 'Assertion'));

        return count($assertions) === 1 ? IssuerReader::unverified($assertions[0], 'saml:Assertion') : null;
    }
}
