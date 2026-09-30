<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Value;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use function mb_strlen;
use function preg_match;

/**
 * A URI (M-6): absolute, a scheme then a colon (SAML Core §1.3.2, RFC 3986 §3.1 and §4.3), no whitespace, no control
 * character and no format character (a right-to-left override, a zero-width space) anywhere, at most 1024 characters counted as code points (SAML Core §8.3.6, section 7). An entity
 * ID, a Destination, a Recipient, an Audience and a Location are URIs of this rule; they are compared as read, never
 * normalised (M-8).
 */
final readonly class Uri
{
    private const int MAX_CHARACTERS = 1024;

    /**
     * @throws MalformedMessage when the value is longer than 1024 characters, holds whitespace, a control or a format
     *                          character or bytes that are not UTF-8, or is not absolute (M-6)
     */
    public static function read(string $value): string
    {
        if (mb_strlen($value, 'UTF-8') > self::MAX_CHARACTERS) {
            throw new MalformedMessage('A URI is longer than 1024 characters (M-6).');
        }
        if (preg_match('~^[^\p{Z}\p{Cc}\p{Cf}]*\z~u', $value) !== 1) {
            throw new MalformedMessage('A URI holds whitespace, a control or format character, or bytes that are not UTF-8 (M-6).');
        }
        if (preg_match('~^[A-Za-z][A-Za-z0-9+.\-]*:~', $value) !== 1) {
            throw new MalformedMessage('A URI is not absolute (M-6).');
        }

        return $value;
    }
}
