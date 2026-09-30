<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Assertion;

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
 * The structure of the elements of an assertion, read strictly (M-4, M-5): direct children only, through Core's
 * Children (I-11), in the order and with the cardinality of the schema; what the package does not support refused by
 * name (section 8); a required attribute present. Nothing is searched, and no refusal carries a value of the input
 * (M-16).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Structure
{
    /**
     * The name of an element of the assertion namespace.
     */
    public static function saml(string $local): Name
    {
        return new Name(Saml::ASSERTION, $local);
    }

    /**
     * The element children of $parent follow $model: each falls in the first particle, at or after the one the
     * previous child fell in, whose names it matches; a particle that does not repeat holds one child at most, and a
     * required one at least one.
     *
     * @param list<Particle> $model
     *
     * @throws MalformedMessage when a child is out of order or not allowed there, repeats where it may not, or is
     *                          missing where it is required
     */
    public static function sequence(Element $parent, array $model, string $label): void
    {
        $occurrences = array_fill(0, count($model), 0);
        $position = 0;
        foreach (Children::all($parent) as $child) {
            $position = self::position($model, $position, $child) ?? throw new MalformedMessage(sprintf(
                'The %s holds a child out of the order of the schema, or one it does not allow there (M-5).',
                $label,
            ));
            if (! $model[$position]->repeated && $occurrences[$position] > 0) {
                throw new MalformedMessage(sprintf(
                    'The %s holds more than one %s (M-4).',
                    $label,
                    $model[$position]->label,
                ));
            }
            ++$occurrences[$position];
        }
        foreach ($model as $index => $particle) {
            if ($particle->required && $occurrences[$index] === 0) {
                throw new MalformedMessage(sprintf('The %s holds no %s (M-4).', $label, $particle->label));
            }
        }
    }

    /**
     * No element child of $parent has one of $names.
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

    /**
     * The value of the attribute $local, in no namespace, as read.
     *
     * @throws MalformedMessage when it is absent
     */
    public static function attribute(Element $element, string $local, string $message): string
    {
        return Attributes::optional($element, new Name(null, $local)) ?? throw new MalformedMessage($message);
    }

    /**
     * The first particle at or after $from that $child matches, or null when none does.
     *
     * @param list<Particle> $model
     */
    private static function position(array $model, int $from, Element $child): ?int
    {
        $counter = count($model);
        for ($position = $from; $position < $counter; ++$position) {
            if ($model[$position]->matches($child)) {
                return $position;
            }
        }

        return null;
    }
}
