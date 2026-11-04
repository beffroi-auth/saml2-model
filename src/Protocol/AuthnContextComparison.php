<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

use Beffroi\Saml2\Model\Exception\MalformedMessage;

/**
 * SAML Core §3.3.2.2.1
 */
enum AuthnContextComparison: string
{
    case Exact = 'exact';
    case Minimum = 'minimum';
    case Maximum = 'maximum';
    case Better = 'better';

    /**
     * @throws MalformedMessage
     */
    public static function fromAttribute(?string $value): self
    {
        if ($value === null) {
            return self::Exact;
        }

        return (
            self::tryFrom($value) ?? throw new MalformedMessage('The Comparison of a samlp:RequestedAuthnContext is not one of exact, minimum, maximum and better (M-5).')
        );
    }
}
