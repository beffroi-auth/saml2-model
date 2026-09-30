<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Writing;

/**
 * What the identity provider signs of a response (section 5.7): the assertion always, since the profile requires a
 * signature over it (SAML Profiles §4.1.4.5, E26, M-2); the response too on request, over the assertion's signature
 * (dsig.md section 5.5).
 */
enum SignedParts
{
    /**
     * The default: the assertion signed, the response not.
     */
    case Assertion;

    /**
     * The assertion signed, then the response over it.
     */
    case AssertionAndResponse;
}
