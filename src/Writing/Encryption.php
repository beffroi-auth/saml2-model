<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Writing;

use Beffroi\Xml\Enc\ContentAlgorithm;
use Beffroi\Xml\Enc\KeyTransport;
use Beffroi\Xml\Enc\OaepHash;
use Beffroi\Xml\Enc\PeerKey;

/**
 * How the response writer encrypts the assertion it signed (sections 5.7 and 6.7): for the key of the service
 * provider, built from an encryption certificate of its metadata, under the content algorithm and the key transport
 * of Enc, aes256-gcm under rsa-oaep-mgf1p by default. Which certificate, and whether a service provider is sent an
 * encrypted assertion at all, is the consumer's (section 6.9).
 */
final readonly class Encryption
{
    public function __construct(
        public PeerKey $peer,
        public ContentAlgorithm $algorithm = ContentAlgorithm::Aes256Gcm,
        public KeyTransport $transport = new KeyTransport(OaepHash::Sha1),
    ) {
    }
}
