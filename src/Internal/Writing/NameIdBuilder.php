<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Writing;

use Beffroi\Saml2\Model\Assertion\NameId;
use Dom\Element;

/**
 * The one writer of a saml:NameID, an assertion's subject and a logout request's principal (section 6.6): its Format
 * always written, the unspecified one as its 1.1 URI (E60), its qualifiers when it has them, then its value as text.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class NameIdBuilder
{
    /**
     * The NameID appended to $parent, where the saml prefix is declared.
     */
    public static function append(Tree $tree, Element $parent, NameId $nameId): void
    {
        $element = $tree->saml($parent, 'NameID');
        $element->setAttribute('Format', $nameId->format->value);
        foreach ([
            'NameQualifier' => $nameId->nameQualifier,
            'SPNameQualifier' => $nameId->spNameQualifier,
            'SPProvidedID' => $nameId->spProvidedId,
        ] as $attribute => $value) {
            if ($value === null) {
                continue;
            }
            $element->setAttribute($attribute, $value);
        }
        $element->append($nameId->value);
    }
}
