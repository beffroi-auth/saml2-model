<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Value;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use function preg_match;

/**
 * XML Schema Part 2 §3.3.23, M-6
 */
final readonly class UnsignedShort
{
    private const int MAX = 65_535;

    /**
     * @throws MalformedMessage
     */
    public static function read(string $value): int
    {
        if (preg_match('~^(?:0|[1-9]\d{0,4})\z~', $value) !== 1) {
            throw self::refusal();
        }

        return self::check((int) $value);
    }

    /**
     * @throws MalformedMessage
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
