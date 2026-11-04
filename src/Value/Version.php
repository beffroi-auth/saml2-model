<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Value;

use Beffroi\Saml2\Model\Exception\MalformedMessage;

/**
 * SAML Core §2.3.3, §3.2.1
 *
 * The string repeats Saml::VERSION: Value depends on nothing of the package but its exceptions.
 */
final readonly class Version
{
    /**
     * @throws MalformedMessage
     */
    public static function read(string $value): string
    {
        if ($value !== '2.0') {
            throw new MalformedMessage('The version is not 2.0 (M-6).');
        }

        return $value;
    }
}
