<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Assertion;

use function array_any;
use Beffroi\Xml\Core\Name;
use Dom\Element;

/**
 * One step of the content model of an element, as the SAML 2.0 schema writes it (M-5): the names an element child may
 * have there, whether one is required, and whether it may repeat. The label names the element in a refusal, never
 * the input (M-16).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Particle
{
    /**
     * @param list<Name> $names
     */
    private function __construct(
        public array $names,
        public string $label,
        public bool $required,
        public bool $repeated,
    ) {
    }

    /**
     * Exactly one element of that name.
     */
    public static function one(Name $name, string $label): self
    {
        return new self([$name], $label, true, false);
    }

    /**
     * At most one element of that name.
     */
    public static function optional(Name $name, string $label): self
    {
        return new self([$name], $label, false, false);
    }

    /**
     * One element of that name or more.
     */
    public static function some(Name $name, string $label): self
    {
        return new self([$name], $label, true, true);
    }

    /**
     * Any number of elements of those names, none included, in any order among themselves: a choice that repeats.
     *
     * @param list<Name> $names
     */
    public static function any(array $names): self
    {
        return new self($names, '', false, true);
    }

    public function matches(Element $child): bool
    {
        return array_any($this->names, static fn (Name $name): bool => $name->matches($child));
    }
}
