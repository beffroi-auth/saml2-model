<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Response;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Dsig\Verified;
use Beffroi\Xml\Enc\CoveringSignatureInterface;

/**
 * enc.md E-15, section 6.7
 *
 * Built from the verification of the response's signature and from nothing else.
 *
 * @internal
 */
final readonly class CoveringResponseSignature implements CoveringSignatureInterface
{
    public function __construct(
        private Verified $verification,
    ) {
    }

    public function document(): Document
    {
        return $this->verification->document;
    }
}
