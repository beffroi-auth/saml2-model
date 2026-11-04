<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Validation;

final readonly class ExpectedResponse
{
    private function __construct(
        public ?string $requestId,
        public string $receivedAt,
        public string $audience,
    ) {
    }

    public static function toRequest(string $requestId, string $receivedAt, string $audience): self
    {
        return new self($requestId, $receivedAt, $audience);
    }

    /**
     * SAML Profiles §4.1.5
     */
    public static function unsolicited(string $receivedAt, string $audience): self
    {
        return new self(null, $receivedAt, $audience);
    }
}
