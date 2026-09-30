<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Assertion;

use Beffroi\Saml2\Model\Exception\MalformedMessage;

/**
 * The three attribute name formats of SAML Core §8.2, a closed vocabulary: fromUri() refuses every other URI (M-5).
 */
enum AttributeNameFormat: string
{
    case Unspecified = 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified';
    case Uri = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';
    case Basic = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';

    /**
     * The NameFormat of a saml:Attribute, null when the attribute is absent, which means Unspecified (SAML Core
     * §2.7.3.1).
     *
     * @throws MalformedMessage for every other URI (M-5)
     */
    public static function fromUri(?string $uri): self
    {
        if ($uri === null) {
            return self::Unspecified;
        }

        return (
            self::tryFrom($uri) ?? throw new MalformedMessage('The NameFormat of an attribute is not one of the three of SAML Core (M-5).')
        );
    }
}
