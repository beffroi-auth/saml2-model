<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Assertion;

use function array_map;
use Beffroi\Saml2\Model\Assertion\Attribute;
use Beffroi\Saml2\Model\Assertion\AttributeNameFormat;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\Unsupported;
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
     * Attributes per statement, section 7.
     */
    private const int MAX_ATTRIBUTES = 256;

    /**
     * Values per attribute, section 7.
     */
    private const int MAX_VALUES = 256;

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
        Structure::unsupported(
            $statement,
            [Structure::saml('EncryptedAttribute')],
            'The attribute statement holds a saml:EncryptedAttribute, which the package does not support until sub-spike 9e (section 6.7).',
        );
        $attributes = Children::named($statement, Structure::saml('Attribute'));
        if (count($attributes) > self::MAX_ATTRIBUTES) {
            throw new LimitExceeded(sprintf(
                'The AttributeStatement holds more than %d Attribute, the bound of section 7 (M-17).',
                self::MAX_ATTRIBUTES,
            ));
        }
        Structure::sequence(
            $statement,
            [Particle::some(Structure::saml('Attribute'), 'saml:Attribute')],
            'saml:AttributeStatement',
        );

        return array_map(self::attribute(...), $attributes);
    }

    private static function attribute(Element $attribute): Attribute
    {
        $values = Children::named($attribute, Structure::saml('AttributeValue'));
        if (count($values) > self::MAX_VALUES) {
            throw new LimitExceeded(sprintf(
                'An Attribute holds more than %d AttributeValue, the bound of section 7 (M-17).',
                self::MAX_VALUES,
            ));
        }
        Structure::sequence($attribute, [Particle::any([Structure::saml('AttributeValue')])], 'saml:Attribute');

        return new Attribute(
            Structure::attribute($attribute, 'Name', 'The saml:Attribute has no Name (M-5).'),
            AttributeNameFormat::fromUri(Attributes::optional($attribute, new Name(null, 'NameFormat'))),
            Attributes::optional($attribute, new Name(null, 'FriendlyName')),
            array_map(Text::of(...), $values),
        );
    }
}
