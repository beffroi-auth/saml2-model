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
 * SAML Core §2.2.3, M-12, I-12
 *
 * @internal
 */
final readonly class NameIdReader
{
    /**
     * @throws InvalidNameId
     * @throws MixedContent
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
