<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal;

use function array_any;
use Beffroi\Xml\Core\Name;
use Dom\Element;
use const PHP_INT_MAX;

/**
 * One place of a sequence of the SAML 2.0 schemas (M-5): the element names it accepts, a choice when there are
 * several, and how many times, from $min to $max.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Particle
{
    public const int UNBOUNDED = PHP_INT_MAX;

    /**
     * @param string $label the name of the place in the schema, for the refusals: never a name read from the input
     * @param list<Name> $names
     */
    public function __construct(
        public string $label,
        public array $names,
        public int $min,
        public int $max,
    ) {
    }

    /**
     * One element name, the prefix of its namespace for label.
     */
    public static function of(Name $name, int $min, int $max): self
    {
        return new self(Schema::label($name), [$name], $min, $max);
    }

    public function matches(Element $element): bool
    {
        return array_any($this->names, static fn (Name $name): bool => $name->matches($element));
    }
}
