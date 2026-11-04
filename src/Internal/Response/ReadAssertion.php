<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Response;

use Beffroi\Saml2\Model\Assertion\Assertion;

/**
 * @internal
 */
final readonly class ReadAssertion
{
    public function __construct(
        public Assertion $assertion,
        public bool $signed,
    ) {
    }
}
