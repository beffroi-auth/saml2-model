<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Writing;

/**
 * The assertion is always signed: the profile requires a signature over it (SAML Profiles §4.1.4.5, E26).
 */
enum SignedParts
{
    case Assertion;

    case AssertionAndResponse;
}
