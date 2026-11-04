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
 * SAML Metadata §2.4.4
 */
final readonly class ServiceProvider
{
    /**
     * @param list<string> $signingCertificates
     * @param list<string> $encryptionCertificates
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

    public function verificationKeys(): ?VerificationKeys
    {
        return RoleRules::verificationKeys($this->signingCertificates);
    }
}
