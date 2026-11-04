<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Assertion;

use Beffroi\Saml2\Model\Exception\MalformedMessage;

/**
 * SAML Core §8.2
 */
enum AttributeNameFormat: string
{
    case Unspecified = 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified';
    case Uri = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';
    case Basic = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';

    /**
     * @throws MalformedMessage
     */
    public static function fromUri(?string $uri): self
    {
        if ($uri === null) {
            return self::Unspecified;
        }

        return self::tryFrom($uri) ?? throw new MalformedMessage('The NameFormat of an attribute is not one of the three of SAML Core (M-5).');
    }
}
