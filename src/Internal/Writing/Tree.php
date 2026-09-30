<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Writing;

use Beffroi\Saml2\Model\Saml;
use Beffroi\Xml\Core\Document;
use Dom\Element;
use Dom\XMLDocument;

/**
 * The elements of a document the package builds, section 6.6 step 2 (core.md section 6.5): each created with
 * createElementNS() and its prefix, samlp or saml, and appended to its parent; the saml namespace declared as an
 * attribute on the element that introduces it under an element of another namespace, never on its descendants.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Tree
{
    private const string XMLNS = 'http://www.w3.org/2000/xmlns/';

    private function __construct(
        private XMLDocument $xml,
    ) {
    }

    /**
     * The tree of a document DocumentFactory created.
     */
    public static function of(Document $document): self
    {
        /** @var XMLDocument $xml DocumentFactory creates an XML document, which owns every element built in it */
        $xml = $document->root()->ownerDocument;

        return new self($xml);
    }

    /**
     * A saml element appended to an element of another namespace, declaring the saml prefix it introduces.
     */
    public function introduceSaml(Element $parent, string $local): Element
    {
        $element = $this->saml($parent, $local);
        $element->setAttributeNS(self::XMLNS, 'xmlns:saml', Saml::ASSERTION);

        return $element;
    }

    /**
     * A saml element appended to an element where the saml prefix is declared.
     */
    public function saml(Element $parent, string $local): Element
    {
        return $this->append($parent, Saml::ASSERTION, 'saml:' . $local);
    }

    /**
     * A samlp element appended to an element where the samlp prefix is declared.
     */
    public function samlp(Element $parent, string $local): Element
    {
        return $this->append($parent, Saml::PROTOCOL, 'samlp:' . $local);
    }

    private function append(Element $parent, string $namespace, string $qualifiedName): Element
    {
        $child = $this->xml->createElementNS($namespace, $qualifiedName);
        $parent->appendChild($child);

        return $child;
    }
}
