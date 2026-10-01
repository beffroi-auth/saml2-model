<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use function count;
use Dom\Element;

/**
 * A samlp:Response as it arrived, before any signature is verified (section 5.4, M-1): the Document the consumer
 * loaded with SamlLoader::create(), held for as long as the validation runs, and the two values the consumer needs to
 * choose the identity provider whose keys verify it, its Issuer and its InResponseTo. They choose a peer and nothing
 * else: ResponseValidator reads both again from what was verified.
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
     * The root checked to be samlp:Response; its Issuer, or the Issuer of its one direct saml:Assertion child when it
     * has none, and its InResponseTo, read and nothing else. Two Issuers where one is read are refused rather than one
     * of them picked (M-4); a response with several assertions and no Issuer of its own names no issuer.
     *
     * @throws MalformedMessage when the root is another element, an Issuer is repeated, or the two values are not of
     *                          their lexical form (M-6)
     * @throws MixedContent when the Issuer holds an element
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
        $name = new Name(Saml::ASSERTION, 'Issuer');
        $issuers = Children::named($response, $name);
        if ($issuers === []) {
            $assertions = Children::named($response, new Name(Saml::ASSERTION, 'Assertion'));
            $issuers = count($assertions) === 1 ? Children::named($assertions[0], $name) : [];
        }
        if (count($issuers) > 1) {
            throw new MalformedMessage('The response or its assertion holds more than one saml:Issuer (M-4).');
        }

        return $issuers === [] ? null : new Issuer(Text::of($issuers[0]))->entityId;
    }
}
