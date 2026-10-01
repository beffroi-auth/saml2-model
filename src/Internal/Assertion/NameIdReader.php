<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Assertion;

use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\InvalidNameId;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use Dom\Element;

/**
 * The one reader of a saml:NameID, an assertion's subject and a logout request's principal (M-12, SAML Core §2.2.3):
 * its value read with Text::of() on the verified document, comments concatenated (I-12), never trimmed; its Format one
 * of SAML Core §8.3, absent meaning unspecified; its three qualifiers as read; the rule of its format applied by NameId.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class NameIdReader
{
    /**
     * @throws InvalidNameId when the Format is not one of SAML Core §8.3, or the value breaks the rule of its format
     *                       (M-12)
     * @throws MixedContent when the element holds an element
     */
    public static function read(Element $nameId): NameId
    {
        return new NameId(
            Text::of($nameId),
            NameIdFormat::fromUri(Attributes::optional($nameId, new Name(null, 'Format'))),
            Attributes::optional($nameId, new Name(null, 'NameQualifier')),
            Attributes::optional($nameId, new Name(null, 'SPNameQualifier')),
            Attributes::optional($nameId, new Name(null, 'SPProvidedID')),
        );
    }
}
