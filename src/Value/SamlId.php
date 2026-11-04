<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Value;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Xml\Core\NcName;
use function bin2hex;
use function random_bytes;
use function strlen;

/**
 * SAML Core §1.3.4, M-6, M-15
 */
final readonly class SamlId
{
    private const int MAX_BYTES = 128;

    /**
     * An underscore, since an NCName does not start with a digit, then 160 random bits (SAML Core §1.3.4).
     */
    public static function generate(): string
    {
        return '_' . bin2hex(random_bytes(20));
    }

    /**
     * @throws MalformedMessage
     */
    public static function read(string $value): string
    {
        if (strlen($value) > self::MAX_BYTES) {
            throw new MalformedMessage('An ID is longer than 128 bytes (M-6).');
        }
        if (! NcName::is($value)) {
            throw new MalformedMessage('An ID is not an NCName (M-6).');
        }

        return $value;
    }
}
