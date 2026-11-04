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
 * M-5
 *
 * @internal
 */
final readonly class Schema
{
    public const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    public const string XMLENC = 'http://www.w3.org/2001/04/xmlenc#';

    public static function saml(string $local): Name
    {
        return new Name(Saml::ASSERTION, $local);
    }

    public static function samlp(string $local): Name
    {
        return new Name(Saml::PROTOCOL, $local);
    }

    public static function md(string $local): Name
    {
        return new Name(Saml::METADATA, $local);
    }

    public static function ds(string $local): Name
    {
        return new Name(self::DSIG, $local);
    }

    public static function xenc(string $local): Name
    {
        return new Name(self::XMLENC, $local);
    }

    public static function label(Name $name): string
    {
        return (
            match ($name->namespace) {
                Saml::PROTOCOL => 'samlp:',
                Saml::METADATA => 'md:',
                self::DSIG => 'ds:',
                self::XMLENC => 'xenc:',
                default => 'saml:',
            } . $name->local
        );
    }

    /**
     * @param string $element the name of $parent in the schema, for the refusals
     * @param list<Particle> $particles
     *
     * @throws MalformedMessage
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
     * @param string $element the name of the element in the schema, for the refusal
     *
     * @throws MalformedMessage
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
