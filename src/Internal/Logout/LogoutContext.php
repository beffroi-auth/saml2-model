<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Logout;

use function array_map;
use Beffroi\Saml2\Model\Internal\Window;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Validation\TimeBounds;
use DateTimeImmutable;
use InvalidArgumentException;

/**
 * @internal
 */
final readonly class LogoutContext
{
    /**
     * @param list<string> $endpoints
     */
    private function __construct(
        public string $peer,
        public string $receivedAt,
        public array $endpoints,
        public Window $window,
    ) {
    }

    /**
     * @throws InvalidArgumentException when $self is not the role that faces $peer's
     */
    public static function forRequest(
        DateTimeImmutable $now,
        TimeBounds $bounds,
        IdentityProvider|ServiceProvider $peer,
        IdentityProvider|ServiceProvider $self,
        string $receivedAt,
    ): self {
        return self::of($now, $bounds, $peer, $self, $receivedAt, array_map(
            static fn (Endpoint $endpoint): string => $endpoint->location,
            $self->singleLogoutServices,
        ));
    }

    /**
     * SAML Metadata §2.2.2
     *
     * @throws InvalidArgumentException when $self is not the role that faces $peer's
     */
    public static function forResponse(
        DateTimeImmutable $now,
        TimeBounds $bounds,
        IdentityProvider|ServiceProvider $peer,
        IdentityProvider|ServiceProvider $self,
        string $receivedAt,
    ): self {
        return self::of($now, $bounds, $peer, $self, $receivedAt, array_map(
            static fn (Endpoint $endpoint): string => $endpoint->responseLocation ?? $endpoint->location,
            $self->singleLogoutServices,
        ));
    }

    /**
     * @param list<string> $endpoints
     *
     * @throws InvalidArgumentException
     */
    private static function of(
        DateTimeImmutable $now,
        TimeBounds $bounds,
        IdentityProvider|ServiceProvider $peer,
        IdentityProvider|ServiceProvider $self,
        string $receivedAt,
        array $endpoints,
    ): self {
        if ($peer instanceof IdentityProvider === $self instanceof IdentityProvider) {
            throw new InvalidArgumentException('Our role is the one that faces the peer\'s, a service provider facing an identity provider or the reverse (section 5.6).');
        }

        return new self($peer->entityId, $receivedAt, $endpoints, new Window($now, $bounds));
    }
}
