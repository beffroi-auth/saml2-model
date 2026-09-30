<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

use Beffroi\Saml2\Model\Exception\MalformedMessage;

/**
 * The comparison a samlp:RequestedAuthnContext asks for (SAML Core §3.3.2.2.1), a closed vocabulary: fromAttribute()
 * refuses every other value (M-5). The model returns it and never enforces it: whether the identity provider can
 * satisfy it is heidi/saml's (section 6.2 step 5).
 */
enum AuthnContextComparison: string
{
    case Exact = 'exact';
    case Minimum = 'minimum';
    case Maximum = 'maximum';
    case Better = 'better';

    /**
     * The Comparison attribute, null when it is absent, which means exact (SAML Core §3.3.2.2.1).
     *
     * @throws MalformedMessage for every other value, compared as a string (M-5)
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
