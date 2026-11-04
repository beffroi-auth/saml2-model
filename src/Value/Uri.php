<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Value;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use function mb_strlen;
use function preg_match;

/**
 * SAML Core §1.3.2, §8.3.6, RFC 3986 §3.1, §4.3, M-6
 */
final readonly class Uri
{
    private const int MAX_CHARACTERS = 1024;

    /**
     * @throws MalformedMessage
     */
    public static function read(string $value): string
    {
        if (mb_strlen($value, 'UTF-8') > self::MAX_CHARACTERS) {
            throw new MalformedMessage('A URI is longer than 1024 characters (M-6).');
        }
        if (preg_match('~^[^\p{Z}\p{Cc}]*\z~u', $value) !== 1 || ! Characters::visible($value)) {
            throw new MalformedMessage('A URI holds whitespace, a control, format or invisible character, or bytes that are not UTF-8 (M-6).');
        }
        if (preg_match('~^[A-Za-z][A-Za-z0-9+.\-]*:~', $value) !== 1) {
            throw new MalformedMessage('A URI is not absolute (M-6).');
        }

        return $value;
    }
}
