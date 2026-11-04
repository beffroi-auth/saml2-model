<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Value;

use Beffroi\Saml2\Model\Exception\MalformedMessage;

/**
 * XML Schema Part 2 §3.2.2.1, M-6
 *
 * Compared as a string, never cast, and with no whitespace around it, although XML Schema collapses it there.
 */
final readonly class Boolean
{
    public const string TRUE = 'true';

    public const string FALSE = 'false';

    /**
     * @throws MalformedMessage
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
