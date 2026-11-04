<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Assertion;

use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Characters;
use Beffroi\Saml2\Model\Value\Counts;
use function count;

/**
 * SAML Core §2.7.3.1
 */
final readonly class Attribute
{
    /**
     * @param list<string> $values
     *
     * @throws LimitExceeded
     * @throws MalformedMessage
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
