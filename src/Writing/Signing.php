<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Writing;

use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\SigningKeyInterface;
use SensitiveParameter;

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
