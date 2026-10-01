<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Validation;

/**
 * Which signature covered the accepted assertion (section 5.5, M-2, SAML Profiles §4.1.4.5 as corrected by E26): its
 * own, the response's, or both, each verified. Keycloak 26.7.4 signs the response and not the assertion by default,
 * SimpleSAMLphp 2.5.3.1 both (section 9.4).
 */
enum SignatureCoverage
{
    /**
     * The assertion's own signature, the response unsigned.
     */
    case Assertion;

    /**
     * The response's signature, the assertion unsigned.
     */
    case Response;

    /**
     * The assertion's signature and the response's over it.
     */
    case AssertionAndResponse;
}
