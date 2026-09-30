<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Writing;

use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\SigningKeyInterface;
use SensitiveParameter;

/**
 * How a writer signs (section 5.7): the Dsig signing port, so that a key management service signs without handing
 * its key over, the algorithm, RSA with SHA-256 by default, and the certificate of the key as a PEM, the KeyInfo
 * hint of D-17 for the peers that want it.
 */
final readonly class Signing
{
    public function __construct(
        public SigningKeyInterface $key,
        public SignatureAlgorithm $algorithm = SignatureAlgorithm::RsaSha256,
        #[SensitiveParameter]
        public ?string $certificatePem = null,
    ) {
    }
}
