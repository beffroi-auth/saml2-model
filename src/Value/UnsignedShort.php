<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Value;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use function preg_match;

/**
 * An index (M-6): an xs:unsignedShort (XML Schema Part 2 §3.3.23), from 0 to 65535, read in its one lexical form,
 * decimal digits without sign, whitespace or leading zero. The index of an md:AssertionConsumerService (SAML Metadata
 * §2.2.3) and the AssertionConsumerServiceIndex of an AuthnRequest (SAML Core §3.4.1) are indexes of this rule,
 * whoever builds them; written as the decimal PHP prints, which is that form (M-15).
 */
final readonly class UnsignedShort
{
    private const int MAX = 65_535;

    /**
     * @throws MalformedMessage when the value is not of the lexical form above, or over 65535 (M-6)
     */
    public static function read(string $value): int
    {
        if (preg_match('~^(?:0|[1-9]\d{0,4})\z~', $value) !== 1) {
            throw self::refusal();
        }

        return self::check((int) $value);
    }

    /**
     * @throws MalformedMessage when the value is under 0 or over 65535 (M-6)
     */
    public static function check(int $value): int
    {
        if ($value < 0 || $value > self::MAX) {
            throw self::refusal();
        }

        return $value;
    }

    private static function refusal(): MalformedMessage
    {
        return new MalformedMessage('An index is not an xs:unsignedShort, digits without sign or leading zero from 0 to 65535 (M-6).');
    }
}
