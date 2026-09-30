<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Validation;

/**
 * What the consumer expects of a response (section 5.5, M-8, M-10): the URL of its assertion consumer service at which
 * the response arrived, its own entity ID, the audience, and the ID of the AuthnRequest it answers, or none for an
 * unsolicited response (SAML Profiles §4.1.5), whose InResponseTo is then absent everywhere. Whether a tenant accepts
 * unsolicited responses at all is the consumer's policy (section 6.9).
 */
final readonly class ExpectedResponse
{
    private function __construct(
        public ?string $requestId,
        public string $receivedAt,
        public string $audience,
    ) {
    }

    /**
     * A response to the AuthnRequest $requestId, received at $receivedAt (the URL of our assertion consumer service),
     * for $audience (our entity ID).
     */
    public static function toRequest(string $requestId, string $receivedAt, string $audience): self
    {
        return new self($requestId, $receivedAt, $audience);
    }

    /**
     * An unsolicited response (SAML Profiles §4.1.5): InResponseTo absent everywhere.
     */
    public static function unsolicited(string $receivedAt, string $audience): self
    {
        return new self(null, $receivedAt, $audience);
    }
}
