<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\AuthnRequest\AssertionConsumerService;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Saml2\Model\Value\UnsignedShort;
use Beffroi\Saml2\Model\Value\Uri;
use DateTimeImmutable;

/**
 * SAML Core §3.4.1
 */
final readonly class AuthnRequest
{
    /**
     * @throws MalformedMessage when a value is not of its lexical form, or the index comes with the URL or the
     *                          ProtocolBinding (M-9)
     * @throws Unsupported when the ProtocolBinding is not HTTP-POST
     */
    public function __construct(
        public string $id,
        public DateTimeImmutable $issueInstant,
        public Issuer $issuer,
        public ?string $destination = null,
        public ?string $assertionConsumerServiceUrl = null,
        public ?int $assertionConsumerServiceIndex = null,
        public ?string $protocolBinding = null,
        public ?NameIdPolicy $nameIdPolicy = null,
        public bool $forceAuthn = false,
        public bool $isPassive = false,
        public ?RequestedAuthnContext $requestedAuthnContext = null,
    ) {
        SamlId::read($id);
        if ($destination !== null) {
            Uri::read($destination);
        }
        if ($assertionConsumerServiceUrl !== null) {
            Uri::read($assertionConsumerServiceUrl);
        }
        if ($assertionConsumerServiceIndex !== null) {
            UnsignedShort::check($assertionConsumerServiceIndex);
        }
        AssertionConsumerService::exclusive(
            $assertionConsumerServiceUrl,
            $assertionConsumerServiceIndex,
            $protocolBinding,
        );
        if ($protocolBinding !== null) {
            AssertionConsumerService::protocolBinding($protocolBinding);
        }
    }
}
