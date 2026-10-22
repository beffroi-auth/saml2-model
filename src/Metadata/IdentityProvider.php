<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Metadata;

use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Metadata\RoleRules;
use Beffroi\Xml\Dsig\Exception\InvalidKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Enc\DecryptionKeyInterface;

/**
 * The md:IDPSSODescriptor of an entity (section 5.3, SAML Metadata §2.4.3): the certificates of its keys, the base64
 * of each X509Certificate, its single sign-on and single logout services, the NameID formats it lists, and whether it
 * wants the requests it receives signed. The keys that verify what it sends are those of its signing certificates
 * (M-3). A writer refuses one without a single sign-on service (section 6.6), which the reader refuses too (section
 * 6.5 step 6).
 *
 * The consumer gives it the service provider's own decryption key whose encryption certificate went to this provider,
 * and to no other (section 5.5, enc.md E-15): the key that opens an encrypted assertion travels with the provider whose
 * metadata verify the response, so that a provider that signs another's ciphertext has it opened under its own key,
 * which does not open it. Metadata never carry it.
 */
final readonly class IdentityProvider
{
    /**
     * @param list<string> $signingCertificates
     * @param list<string> $encryptionCertificates
     * @param list<Endpoint> $singleSignOnServices
     * @param list<Endpoint> $singleLogoutServices
     * @param list<NameIdFormat> $nameIdFormats
     * @param ?DecryptionKeyInterface $decryptionKey the service provider's key whose encryption certificate went to this
     *                                               provider, null when none did (section 5.5)
     *
     * @throws MalformedMessage when the entity ID is not a URI of M-6
     * @throws LimitExceeded when a list is over its bound of section 7 (M-17)
     * @throws InvalidKey when a certificate is not the base64 of an RSA key of at least 2048 bits (D-16)
     */
    public function __construct(
        public string $entityId,
        public array $signingCertificates,
        public array $encryptionCertificates,
        public array $singleSignOnServices,
        public array $singleLogoutServices = [],
        public array $nameIdFormats = [],
        public bool $wantAuthnRequestsSigned = false,
        public ?DecryptionKeyInterface $decryptionKey = null,
    ) {
        RoleRules::checkEndpoints($singleSignOnServices, 'single sign-on services');
        RoleRules::check(
            $entityId,
            $signingCertificates,
            $encryptionCertificates,
            $singleLogoutServices,
            $nameIdFormats,
        );
    }

    /**
     * The same provider, given the service provider's key whose encryption certificate went to it (section 5.5).
     *
     * @throws MalformedMessage never, the constructor having accepted this provider already
     * @throws LimitExceeded never, for the same reason
     * @throws InvalidKey never, for the same reason
     */
    public function withDecryptionKey(DecryptionKeyInterface $decryptionKey): self
    {
        return new self(
            $this->entityId,
            $this->signingCertificates,
            $this->encryptionCertificates,
            $this->singleSignOnServices,
            $this->singleLogoutServices,
            $this->nameIdFormats,
            $this->wantAuthnRequestsSigned,
            $decryptionKey,
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
