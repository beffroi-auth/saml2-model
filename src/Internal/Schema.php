<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal;

use function array_any;
use function array_fill;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use function count;
use Dom\Element;
use function sprintf;

/**
 * The one reading model of the SAML 2.0 schemas, for every element the package reads (M-5): the names of its four
 * vocabularies, the children of an element in the order and with the cardinality of its sequence, found as direct
 * children through Core's Children (M-4, I-11), the attributes it requires, and what the package does not support,
 * refused by name (section 8). Nothing is searched, and every refusal names the place of the schema, never what the
 * input holds (M-16).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Schema
{
    public const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * The name of an element of the assertion namespace.
     */
    public static function saml(string $local): Name
    {
        return new Name(Saml::ASSERTION, $local);
    }

    /**
     * The name of an element of the protocol namespace.
     */
    public static function samlp(string $local): Name
    {
        return new Name(Saml::PROTOCOL, $local);
    }

    /**
     * The name of an element of the metadata namespace.
     */
    public static function md(string $local): Name
    {
        return new Name(Saml::METADATA, $local);
    }

    /**
     * The name of an element of the XML Signature namespace.
     */
    public static function ds(string $local): Name
    {
        return new Name(self::DSIG, $local);
    }

    /**
     * The name of the schema with the prefix of its namespace, samlp:, md:, ds: or saml:, as the refusals print it.
     */
    public static function label(Name $name): string
    {
        return (
            match ($name->namespace) {
                Saml::PROTOCOL => 'samlp:',
                Saml::METADATA => 'md:',
                self::DSIG => 'ds:',
                default => 'saml:',
            } . $name->local
        );
    }

    /**
     * The element children of $parent, each in the place of $particles it takes, in order: a child that no place at
     * or after the current one accepts is unknown or out of order, a place holds at most its maximum and at least its
     * minimum.
     *
     * @param string $element the name of $parent in the schema, for the refusals
     * @param list<Particle> $particles
     *
     * @throws MalformedMessage when a child is out of order or not allowed there (M-5), repeats where it may not, or
     *                          is missing where it is required (M-4)
     *
     * @return list<list<Element>> the children of each place, in the order of $particles
     */
    public static function children(Element $parent, string $element, array $particles): array
    {
        /** @var list<list<Element>> $children */
        $children = array_fill(0, count($particles), []);
        $place = 0;
        foreach (Children::all($parent) as $child) {
            while ($place < count($particles) && ! $particles[$place]->matches($child)) {
                $place++;
            }
            if ($place === count($particles)) {
                throw new MalformedMessage(sprintf(
                    'The %s holds a child out of the order of the schema, or one it does not allow there (M-5).',
                    $element,
                ));
            }
            $children[$place][] = $child;
            if (count($children[$place]) > $particles[$place]->max) {
                throw new MalformedMessage(sprintf(
                    'The %s holds more than one %s (M-4).',
                    $element,
                    $particles[$place]->label,
                ));
            }
        }
        foreach ($particles as $index => $particle) {
            if (count($children[$index]) < $particle->min) {
                throw new MalformedMessage(sprintf('The %s holds no %s (M-4).', $element, $particle->label));
            }
        }

        return $children;
    }

    /**
     * An attribute in no namespace that the schema requires, as read.
     *
     * @param string $element the name of the element in the schema, for the refusal
     *
     * @throws MalformedMessage when it is absent (M-5)
     */
    public static function attribute(Element $parent, string $element, string $attribute): string
    {
        return (
            Attributes::optional($parent, new Name(null, $attribute)) ?? throw new MalformedMessage(sprintf(
                'The %s has no %s (M-5).',
                $element,
                $attribute,
            ))
        );
    }

    /**
     * No element child of $parent has one of $names: what the package does not support, refused by name wherever the
     * schema would put it (section 8).
     *
     * @param list<Name> $names
     *
     * @throws Unsupported
     */
    public static function unsupported(Element $parent, array $names, string $message): void
    {
        foreach (Children::all($parent) as $child) {
            if (array_any($names, static fn (Name $name): bool => $name->matches($child))) {
                throw new Unsupported($message);
            }
        }
    }
}
