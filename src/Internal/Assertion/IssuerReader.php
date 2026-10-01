<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Assertion;

use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\IssuerMismatch;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use Dom\Element;

/**
 * A saml:Issuer read strictly (M-8, SAML Profiles §4.1.4.1, §4.1.4.2, §4.4.4.1, §4.4.4.2): its Format omitted or
 * entity, its value read with Text::of() (I-12), a URI of M-6, and the entity ID of the peer, compared exactly.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class IssuerReader
{
    /**
     * @throws IssuerMismatch when the Format is not entity, or the value is not $peer (M-8)
     * @throws MalformedMessage when the value is not a URI of M-6
     * @throws MixedContent when the element holds an element
     */
    public static function read(Element $issuer, string $peer): Issuer
    {
        $format = Attributes::optional($issuer, new Name(null, 'Format'));
        if ($format !== null && $format !== NameIdFormat::Entity->value) {
            throw new IssuerMismatch('The Issuer has a Format other than entity (M-8).');
        }
        $read = new Issuer(Text::of($issuer));
        if ($read->entityId !== $peer) {
            throw new IssuerMismatch('The Issuer is not the entity ID of the peer (M-8).');
        }

        return $read;
    }
}
