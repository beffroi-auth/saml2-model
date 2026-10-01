<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\AuthnRequest\AssertionConsumerService;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Saml2\Model\Value\Uri;
use DateTimeImmutable;

/**
 * A samlp:AuthnRequest (SAML Core §3.4.1, section 5.3), whoever builds it, the validator of the identity provider or
 * the service provider that writes it: its ID, an NCName (M-6), drawn by SamlId::generate() when it is written (M-15);
 * its IssueInstant; its Issuer, the service provider; its Destination, a URI; where the response goes, an
 * AssertionConsumerServiceURL or an AssertionConsumerServiceIndex, mutually exclusive, or neither for the default of
 * the metadata (M-9), and its ProtocolBinding, the URI of HTTP-POST (section 8); then what the identity provider is
 * asked, returned and never enforced: the NameIDPolicy, ForceAuthn, IsPassive and the requested authentication
 * context (section 6.2 step 5).
 */
final readonly class AuthnRequest
{
    private const int MAX_INDEX = 65_535;

    /**
     * @throws MalformedMessage when the ID is not an NCName of at most 128 bytes, the Destination or the
     *                          AssertionConsumerServiceURL is not a URI (M-6), the index is not an
     *                          xs:unsignedShort (M-6), or the index is next to the URL or the ProtocolBinding (M-9)
     * @throws Unsupported when the ProtocolBinding is not HTTP-POST (section 8)
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
        if (
            $assertionConsumerServiceIndex !== null
            && ($assertionConsumerServiceIndex < 0 || $assertionConsumerServiceIndex > self::MAX_INDEX)
        ) {
            throw new MalformedMessage('The AssertionConsumerServiceIndex of an AuthnRequest is not an xs:unsignedShort, from 0 to 65535 (M-6).');
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
