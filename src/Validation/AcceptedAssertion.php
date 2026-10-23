<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Validation;

use Beffroi\Saml2\Model\Assertion\Assertion;

/**
 * What ResponseValidator accepted (section 5.5): the ID of the response, read from the verified response when it is
 * signed and from the received one otherwise (section 6.1 step 6); the assertion, its values copied out of the
 * verified document (M-1), so that nothing of the result depends on a Document being held; and which signature
 * covered it (M-2); and whether it arrived as a saml:EncryptedAssertion the model decrypted or as a saml:Assertion in
 * clear, read from the envelope and never from the assertion (M-18), which the model decides nothing on and a consumer
 * that requires a peer to encrypt refuses on. The consumer reads this and never the document again.
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
