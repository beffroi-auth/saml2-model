<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Value;

use function preg_match;

/**
 * The characters a value may hold, two rules the value objects share. What XML 1.0 carries (XML 1.0 §2.2, Char): a
 * value read from a document always holds only those, and one built by the consumer is held to them, so that a writer
 * never hands the DOM a string it truncates at a NUL or a byte the reload refuses (M-15). What is visible (M-6, M-12):
 * no Unicode format character (\p{Cf}: a right-to-left override U+202E, a zero-width space U+200B) and none of the
 * default-ignorable code points of other categories or blank fillers that render as nothing (U+034F, U+115F, U+1160,
 * U+17B4, U+17B5, U+180B to U+180F, U+2065, U+2800, U+3164, U+FE00 to U+FE0F, U+FFA0, U+FFF0 to U+FFF8, U+E0000 to
 * U+E0FFF), listed rather than read as \p{DI}, which a PCRE before 10.40 does not know. Bytes that are not UTF-8 fail
 * both.
 */
final readonly class Characters
{
    private const string XML = '~^[\x{9}\x{A}\x{D}\x{20}-\x{D7FF}\x{E000}-\x{FFFD}\x{10000}-\x{10FFFF}]*\z~u';

    private const string INVISIBLE = '~[\p{Cf}\x{34F}\x{115F}\x{1160}\x{17B4}\x{17B5}\x{180B}-\x{180F}\x{2065}\x{2800}\x{3164}\x{FE00}-\x{FE0F}\x{FFA0}\x{FFF0}-\x{FFF8}\x{E0000}-\x{E0FFF}]~u';

    /**
     * Whether every character of the value is one XML 1.0 carries, in UTF-8.
     */
    public static function carriedByXml(string $value): bool
    {
        return preg_match(self::XML, $value) === 1;
    }

    /**
     * Whether the value, in UTF-8, holds no invisible character of the list above.
     */
    public static function visible(string $value): bool
    {
        return preg_match(self::INVISIBLE, $value) === 0;
    }
}
