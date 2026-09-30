<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Assertion;

/**
 * A saml:Attribute of the attribute statement (SAML Core §2.7.3.1), as read (section 6.1 step 11): its Name, its
 * NameFormat, its FriendlyName, and the text of each of its values in document order, read with Text::of() on the
 * verified document. An xsi:type on a value is not kept, never resolved (dsig.md §6.3). Two attributes of one name are
 * two objects, never merged: whether they are one claim is the consumer's mapping.
 */
final readonly class Attribute
{
    /**
     * @param list<string> $values
     */
    public function __construct(
        public string $name,
        public AttributeNameFormat $nameFormat,
        public ?string $friendlyName,
        public array $values,
    ) {
    }
}
