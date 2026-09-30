<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Value;

use Beffroi\Saml2\Model\Exception\MalformedMessage;

/**
 * The Version of a message or an assertion (M-6): exactly 2.0 (SAML Core §2.3.3, §3.2.1), the Saml::VERSION the
 * package writes; Value depends on nothing of the package but its exceptions, which is why the string is repeated.
 */
final readonly class Version
{
    /**
     * @throws MalformedMessage for every other string (M-6)
     */
    public static function read(string $value): string
    {
        if ($value !== '2.0') {
            throw new MalformedMessage('The version is not 2.0 (M-6).');
        }

        return $value;
    }
}
