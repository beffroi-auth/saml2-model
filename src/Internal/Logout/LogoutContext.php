<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Logout;

use function array_map;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use DateTimeImmutable;
use InvalidArgumentException;
use function sprintf;

/**
 * What the rules of a logout message are checked against (sections 6.3 and 6.4), as the validator states it: the
 * entity ID of the peer (M-8); the URL at which the message arrived, and those of our single logout services where it
 * may arrive, the Location of each for a request, its ResponseLocation or else its Location for a response (SAML
 * Metadata §2.2.2, section 5.6); the three instants of M-7 from now, read once from the clock, and the time bounds of
 * section 7.
 *
 * @internal
 */
final readonly class LogoutContext
{
    /**
     * @param list<string> $endpoints
     * @param DateTimeImmutable $latest now plus the clock skew: an IssueInstant later than this is refused (M-7)
     * @param DateTimeImmutable $oldest now minus maxMessageAge: an IssueInstant earlier than this is refused (M-7)
     * @param DateTimeImmutable $expired now minus the clock skew: a NotOnOrAfter at or before this is refused (M-7)
     */
    private function __construct(
        public string $peer,
        public string $receivedAt,
        public array $endpoints,
        public DateTimeImmutable $latest,
        public DateTimeImmutable $oldest,
        public DateTimeImmutable $expired,
    ) {
    }

    /**
     * A LogoutRequest arrives at the Location of one of our single logout services.
     *
     * @throws InvalidArgumentException when $self is not the role that faces $peer's (section 5.6)
     */
    public static function forRequest(
        DateTimeImmutable $now,
        int $clockSkew,
        int $maxMessageAge,
        IdentityProvider|ServiceProvider $peer,
        IdentityProvider|ServiceProvider $self,
        string $receivedAt,
    ): self {
        return self::of($now, $clockSkew, $maxMessageAge, $peer, $self, $receivedAt, array_map(
            static fn (Endpoint $endpoint): string => $endpoint->location,
            $self->singleLogoutServices,
        ));
    }

    /**
     * A LogoutResponse arrives at the ResponseLocation of one of our single logout services, or at its Location when
     * it has none (SAML Metadata §2.2.2).
     *
     * @throws InvalidArgumentException when $self is not the role that faces $peer's (section 5.6)
     */
    public static function forResponse(
        DateTimeImmutable $now,
        int $clockSkew,
        int $maxMessageAge,
        IdentityProvider|ServiceProvider $peer,
        IdentityProvider|ServiceProvider $self,
        string $receivedAt,
    ): self {
        return self::of($now, $clockSkew, $maxMessageAge, $peer, $self, $receivedAt, array_map(
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
        int $clockSkew,
        int $maxMessageAge,
        IdentityProvider|ServiceProvider $peer,
        IdentityProvider|ServiceProvider $self,
        string $receivedAt,
        array $endpoints,
    ): self {
        if ($peer instanceof IdentityProvider === $self instanceof IdentityProvider) {
            throw new InvalidArgumentException('Our role is the one that faces the peer\'s, a service provider facing an identity provider or the reverse (section 5.6).');
        }

        return new self(
            $peer->entityId,
            $receivedAt,
            $endpoints,
            $now->modify(sprintf('+%d seconds', $clockSkew)),
            $now->modify(sprintf('-%d seconds', $maxMessageAge)),
            $now->modify(sprintf('-%d seconds', $clockSkew)),
        );
    }
}
