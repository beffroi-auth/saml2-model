<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

/**
 * The status of a response or of a logout response (SAML Core §3.2.2): its top-level code, and its second-level code
 * when it has one SAML Core lists. The StatusMessage and the StatusDetail are not kept: text and content the peer
 * chose, which no refusal carries (M-13, M-16).
 */
final readonly class Status
{
    public function __construct(
        public StatusCode $code,
        public ?SecondLevelStatusCode $secondLevel = null,
    ) {
    }
}
