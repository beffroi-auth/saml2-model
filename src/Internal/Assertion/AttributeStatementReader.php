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
 * Section 6.1 step 11
 *
 * An xsi:type on a value is never read, its prefix never resolved (dsig.md §6.3).
 *
 * @internal
 */
final readonly class AttributeStatementReader
{
    /**
     * @return list<Attribute>
     *
     * @throws Unsupported
     * @throws LimitExceeded
     * @throws MalformedMessage
     * @throws MixedContent
     */
    public static function read(Element $statement): array
    {
        Schema::unsupported(
            $statement,
            [Schema::saml('EncryptedAttribute')],
            'The attribute statement holds a saml:EncryptedAttribute, which the package does not support (section 6.7).',
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
