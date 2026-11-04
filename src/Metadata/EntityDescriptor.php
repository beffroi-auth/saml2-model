<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Metadata;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Uri;
use DateTimeImmutable;
use InvalidArgumentException;

/**
 * SAML Metadata §2.3.2
 *
 * The cacheDuration, in seconds, is written when given and never read: a document read back carries null.
 */
final readonly class EntityDescriptor
{
    /**
     * @throws MalformedMessage
     * @throws InvalidArgumentException when a role carries another entity ID, or the cacheDuration is under one second
     */
    public function __construct(
        public string $entityId,
        public ?DateTimeImmutable $validUntil = null,
        public ?IdentityProvider $identityProvider = null,
        public ?ServiceProvider $serviceProvider = null,
        public ?int $cacheDuration = null,
    ) {
        Uri::read($entityId);
        if ($cacheDuration !== null && $cacheDuration < 1) {
            throw new InvalidArgumentException('The cacheDuration of an entity descriptor is a number of seconds, one at least (section 5.3).');
        }
        if ($identityProvider instanceof IdentityProvider && $identityProvider->entityId !== $entityId) {
            throw new InvalidArgumentException('The identity provider carries the entity ID of its descriptor (section 5.3).');
        }
        if ($serviceProvider instanceof ServiceProvider && $serviceProvider->entityId !== $entityId) {
            throw new InvalidArgumentException('The service provider carries the entity ID of its descriptor (section 5.3).');
        }
    }
}
