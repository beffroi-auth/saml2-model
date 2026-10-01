<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Assertion;

use function array_map;
use Beffroi\Saml2\Model\Assertion\Attribute;
use Beffroi\Saml2\Model\Assertion\AttributeNameFormat;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Particle;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Value\Counts;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use function count;
use Dom\Element;
use function sprintf;

/**
 * The attribute statement of an assertion, section 6.1 step 11: its saml:Attribute elements in document order, a name
 * repeated kept as read and never merged, each with its Name, a NameFormat of SAML Core §8.2, its FriendlyName and the
 * text of its values read with Text::of() (I-12); an xsi:type on a value is not read, its prefix never resolved
 * (dsig.md §6.3); a value holding an element is Core's MixedContent; saml:EncryptedAttribute is refused by name until
 * sub-spike 9e (section 6.7); the counts of section 7 checked before the lists are read (M-17).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class AttributeStatementReader
{
    /**
     * @return list<Attribute>
     *
     * @throws Unsupported when the statement holds a saml:EncryptedAttribute (section 6.7)
     * @throws LimitExceeded when a count is over its bound of section 7 (M-17)
     * @throws MalformedMessage when an element is missing or not allowed, a Name is missing, or a NameFormat is not one
     *                          of SAML Core (M-4, M-5)
     * @throws MixedContent when a value holds an element
     */
    public static function read(Element $statement): array
    {
        Schema::unsupported(
            $statement,
            [Schema::saml('EncryptedAttribute')],
            'The attribute statement holds a saml:EncryptedAttribute, which the package does not support until sub-spike 9e (section 6.7).',
        );
        $attributes = Children::named($statement, Schema::saml('Attribute'));
        Counts::check(
            count($attributes),
            Counts::ATTRIBUTES,
            sprintf(
                'The AttributeStatement holds more than %d Attribute, the bound of section 7 (M-17).',
                Counts::ATTRIBUTES,
            ),
        );
        Schema::children($statement, 'saml:AttributeStatement', [Particle::of(
            Schema::saml('Attribute'),
            1,
            Particle::UNBOUNDED,
        )]);

        return array_map(self::attribute(...), $attributes);
    }

    private static function attribute(Element $attribute): Attribute
    {
        $values = Children::named($attribute, Schema::saml('AttributeValue'));
        Counts::check(
            count($values),
            Counts::ATTRIBUTE_VALUES,
            sprintf(
                'An Attribute holds more than %d AttributeValue, the bound of section 7 (M-17).',
                Counts::ATTRIBUTE_VALUES,
            ),
        );
        Schema::children($attribute, 'saml:Attribute', [Particle::of(
            Schema::saml('AttributeValue'),
            0,
            Particle::UNBOUNDED,
        )]);

        return new Attribute(
            Schema::attribute($attribute, 'saml:Attribute', 'Name'),
            AttributeNameFormat::fromUri(Attributes::optional($attribute, new Name(null, 'NameFormat'))),
            Attributes::optional($attribute, new Name(null, 'FriendlyName')),
            array_map(Text::of(...), $values),
        );
    }
}
