<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

/**
 * SAML Core §3.2.2
 *
 * The StatusMessage and the StatusDetail are not kept: text and content the peer chose, which no refusal carries
 * (M-16).
 */
final readonly class Status
{
    public function __construct(
        public StatusCode $code,
        public ?SecondLevelStatusCode $secondLevel = null,
    ) {
    }
}
