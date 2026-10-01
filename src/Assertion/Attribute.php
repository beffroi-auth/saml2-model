<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Assertion;

use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Characters;
use Beffroi\Saml2\Model\Value\Counts;
use function count;

/**
 * A saml:Attribute of the attribute statement (SAML Core §2.7.3.1), as read (section 6.1 step 11): its Name, its
 * NameFormat, its FriendlyName, and the text of each of its values in document order, read with Text::of() on the
 * verified document. An xsi:type on a value is not kept, never resolved (dsig.md §6.3). Two attributes of one name are
 * two objects, never merged: whether they are one claim is the consumer's mapping. Whoever builds it, its values are
 * at most the count of section 7, and its name, friendly name and values hold only characters XML carries (M-15,
 * M-17).
 */
final readonly class Attribute
{
    /**
     * @param list<string> $values
     *
     * @throws LimitExceeded when there are more than 256 values (section 7)
     * @throws MalformedMessage when the name, the friendly name or a value holds a character XML does not carry (M-15)
     */
    public function __construct(
        public string $name,
        public AttributeNameFormat $nameFormat,
        public ?string $friendlyName,
        public array $values,
    ) {
        Counts::check(
            count($values),
            Counts::ATTRIBUTE_VALUES,
            'An Attribute holds more than 256 AttributeValue, the bound of section 7 (M-17).',
        );
        foreach ([$name, $friendlyName ?? '', ...$values] as $text) {
            if (! Characters::carriedByXml($text)) {
                throw new MalformedMessage('An Attribute holds a character XML does not carry, a NUL among them (M-15).');
            }
        }
    }
}
