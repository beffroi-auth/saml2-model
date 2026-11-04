<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Validation;

use Beffroi\Saml2\Model\Assertion\Assertion;

/**
 * The response ID is the received one when the response is unsigned (section 6.1 step 6). The model decides nothing
 * on $encrypted: a consumer that requires a peer to encrypt refuses on it (M-18).
 */
final readonly class AcceptedAssertion
{
    public function __construct(
        public string $responseId,
        public Assertion $assertion,
        public SignatureCoverage $coverage,
        public bool $encrypted,
    ) {
    }
}
