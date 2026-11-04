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
 * SAML Metadata §2.4.3
 *
 * Its decryption key is the one whose certificate went to this provider and to no other: a provider that signs
 * another's ciphertext has it opened under its own key, which does not open it (enc.md E-15).
 */
final readonly class IdentityProvider
{
    /**
     * @param list<string> $signingCertificates
     * @param list<string> $encryptionCertificates
     * @param list<Endpoint> $singleSignOnServices
     * @param list<Endpoint> $singleLogoutServices
     * @param list<NameIdFormat> $nameIdFormats
     *
     * @throws MalformedMessage
     * @throws LimitExceeded
     * @throws InvalidKey
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
     * @throws MalformedMessage never: the constructor accepted this provider already
     * @throws LimitExceeded never
     * @throws InvalidKey never
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

    public function verificationKeys(): ?VerificationKeys
    {
        return RoleRules::verificationKeys($this->signingCertificates);
    }
}
