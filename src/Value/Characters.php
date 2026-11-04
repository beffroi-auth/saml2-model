<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Value;

use function preg_match;

/**
 * The default-ignorable code points are listed rather than read as \p{DI}, which a PCRE before 10.40 does not know.
 */
final readonly class Characters
{
    private const string XML = '~^[\x{9}\x{A}\x{D}\x{20}-\x{D7FF}\x{E000}-\x{FFFD}\x{10000}-\x{10FFFF}]*\z~u';

    private const string INVISIBLE = '~[\p{Cf}\x{34F}\x{115F}\x{1160}\x{17B4}\x{17B5}\x{180B}-\x{180F}\x{2065}\x{2800}\x{3164}\x{FE00}-\x{FE0F}\x{FFA0}\x{FFF0}-\x{FFF8}\x{E0000}-\x{E0FFF}]~u';

    /**
     * XML 1.0 §2.2
     */
    public static function carriedByXml(string $value): bool
    {
        return preg_match(self::XML, $value) === 1;
    }

    public static function visible(string $value): bool
    {
        return preg_match(self::INVISIBLE, $value) === 0;
    }
}
