<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Response;

use Beffroi\Saml2\Model\Assertion\Assertion;

/**
 * What section 6.1 steps 5 and 7 to 12 read of an assertion, in clear or encrypted: its values, copied out of the
 * document a signature covered (M-1), and whether it carried a signature of its own, which the coverage of the result
 * says (section 5.5).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class ReadAssertion
{
    public function __construct(
        public Assertion $assertion,
        public bool $signed,
    ) {
    }
}
