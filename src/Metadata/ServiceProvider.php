<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Metadata;

use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Metadata\RoleRules;
use Beffroi\Xml\Dsig\Exception\InvalidKey;
use Beffroi\Xml\Dsig\VerificationKeys;

/**
 * The md:SPSSODescriptor of an entity (section 5.3, SAML Metadata §2.4.4): the certificates of its keys, the base64
 * of each X509Certificate, its assertion consumer services on HTTP-POST, where an assertion may go (M-9), its single
 * logout services, the NameID formats it lists, whether it signs its requests and whether it wants the assertions it
 * receives signed. A writer refuses one without an assertion consumer service (section 6.6), which the reader refuses
 * too (section 6.5 step 6).
 */
final readonly class ServiceProvider
{
    /**
     * @param list<string> $signingCertificates
     * @param list<string> $encryptionCertificates
     * @param list<Endpoint> $singleLogoutServices
     * @param list<NameIdFormat> $nameIdFormats
     *
     * @throws MalformedMessage when the entity ID is not a URI of M-6
     * @throws LimitExceeded when a list is over its bound of section 7 (M-17)
     * @throws InvalidKey when a certificate is not the base64 of an RSA key of at least 2048 bits (D-16)
     */
    public function __construct(
        public string $entityId,
        public array $signingCertificates,
        public array $encryptionCertificates,
        public IndexedEndpoints $assertionConsumerServices,
        public array $singleLogoutServices = [],
        public array $nameIdFormats = [],
        public bool $authnRequestsSigned = false,
        public bool $wantAssertionsSigned = false,
    ) {
        RoleRules::check(
            $entityId,
            $signingCertificates,
            $encryptionCertificates,
            $singleLogoutServices,
            $nameIdFormats,
        );
    }

    /**
     * The Dsig keys of the signing certificates (M-3), a key without use included (SAML Metadata §2.4.1.1, E68), or
     * null when the role has none: a validator that needs them refuses the message with SignatureRequired.
     */
    public function verificationKeys(): ?VerificationKeys
    {
        return RoleRules::verificationKeys($this->signingCertificates);
    }
}
