<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Validation;

/**
 * M-2, SAML Profiles §4.1.4.5, E26
 */
enum SignatureCoverage
{
    case Assertion;

    case Response;

    case AssertionAndResponse;
}
