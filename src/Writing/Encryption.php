<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Writing;

use Beffroi\Xml\Enc\ContentAlgorithm;
use Beffroi\Xml\Enc\KeyTransport;
use Beffroi\Xml\Enc\OaepHash;
use Beffroi\Xml\Enc\PeerKey;

final readonly class Encryption
{
    public function __construct(
        public PeerKey $peer,
        public ContentAlgorithm $algorithm = ContentAlgorithm::Aes256Gcm,
        public KeyTransport $transport = new KeyTransport(OaepHash::Sha1),
    ) {
    }
}
