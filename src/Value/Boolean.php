<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Value;

use Beffroi\Saml2\Model\Exception\MalformedMessage;

/**
 * A boolean (M-6): one of the four lexical forms of XML Schema Part 2 §3.2.2.1, true, false, 1 and 0, compared as a
 * string and never cast; nothing around it, although XML Schema collapses whitespace there. Written true or false,
 * the two constants below, which a writer chooses between (M-15).
 */
final readonly class Boolean
{
    public const string TRUE = 'true';

    public const string FALSE = 'false';

    /**
     * @throws MalformedMessage for every other string (M-6)
     */
    public static function read(string $value): bool
    {
        return match ($value) {
            'true', '1' => true,
            'false', '0' => false,
            default => throw new MalformedMessage('A boolean is not one of true, false, 1 and 0 (M-6).'),
        };
    }
}
