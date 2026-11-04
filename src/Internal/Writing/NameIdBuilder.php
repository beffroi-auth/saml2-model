<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Writing;

use Beffroi\Saml2\Model\Assertion\NameId;
use Dom\Element;

/**
 * @internal
 */
final readonly class NameIdBuilder
{
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
