<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Value;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Xml\Core\NcName;
use function bin2hex;
use function random_bytes;
use function strlen;

/**
 * A SAML identifier (M-6, M-15): an ID, and an InResponseTo that names one, are NCNames (SAML Core §1.3.4, core.md
 * I-8) of at most 128 bytes, the maxIdLength of Core (section 7); an ID the package writes holds 160 random bits.
 */
final readonly class SamlId
{
    private const int MAX_BYTES = 128;

    /**
     * An underscore, since an NCName does not start with a digit, then the 40 lowercase hexadecimal digits of 160
     * bits of random_bytes() (SAML Core §1.3.4, M-15).
     */
    public static function generate(): string
    {
        return '_' . bin2hex(random_bytes(20));
    }

    /**
     * @throws MalformedMessage when the value is longer than 128 bytes or is not an NCName (M-6)
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
