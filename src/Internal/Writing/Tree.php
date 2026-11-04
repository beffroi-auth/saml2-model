<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Writing;

use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Xml\Core\Document;
use Dom\Element;
use Dom\XMLDocument;

/**
 * Section 6.6 step 2, core.md section 6.5
 *
 * @internal
 */
final readonly class Tree
{
    private const string XMLNS = 'http://www.w3.org/2000/xmlns/';

    private function __construct(
        private XMLDocument $xml,
    ) {
    }

    public static function of(Document $document): self
    {
        /** @var XMLDocument $xml */
        $xml = $document->root()->ownerDocument;

        return new self($xml);
    }

    public function introduceSaml(Element $parent, string $local): Element
    {
        $element = $this->saml($parent, $local);
        $element->setAttributeNS(self::XMLNS, 'xmlns:saml', Saml::ASSERTION);

        return $element;
    }

    public function saml(Element $parent, string $local): Element
    {
        return $this->append($parent, Saml::ASSERTION, 'saml:' . $local);
    }

    public function samlp(Element $parent, string $local): Element
    {
        return $this->append($parent, Saml::PROTOCOL, 'samlp:' . $local);
    }

    public function md(Element $parent, string $local): Element
    {
        return $this->append($parent, Saml::METADATA, 'md:' . $local);
    }

    public function introduceDs(Element $parent, string $local): Element
    {
        $element = $this->ds($parent, $local);
        $element->setAttributeNS(self::XMLNS, 'xmlns:ds', Schema::DSIG);

        return $element;
    }

    public function ds(Element $parent, string $local): Element
    {
        return $this->append($parent, Schema::DSIG, 'ds:' . $local);
    }

    private function append(Element $parent, string $namespace, string $qualifiedName): Element
    {
        $child = $this->xml->createElementNS($namespace, $qualifiedName);
        $parent->appendChild($child);

        return $child;
    }
}
