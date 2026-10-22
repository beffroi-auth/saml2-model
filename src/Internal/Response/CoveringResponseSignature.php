<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Response;

use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Dsig\Verified;
use Beffroi\Xml\Enc\CoveringSignatureInterface;

/**
 * The proof Enc asks for before it opens AES-CBC (enc.md E-15, section 6.7): the signature of the response, verified
 * at section 6.1 step 3 under the keys of the identity provider's metadata (M-3), whose document is the response that
 * signature covers, its xenc:EncryptedData among its nodes. It is built from that verification and from nothing else.
 *
 * @internal outside the compatibility promise of section 5
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
