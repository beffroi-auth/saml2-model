<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Metadata;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Uri;
use DateTimeImmutable;
use InvalidArgumentException;

/**
 * An md:EntityDescriptor (section 5.3, SAML Metadata §2.3.2): the entity ID, a URI of M-6, the validUntil when the
 * metadata carries one, and the identity provider and service provider roles, each null when absent. A role carries
 * the entity ID of its descriptor. The cacheDuration, in seconds, is what the writer writes when its consumer gives
 * one, and what the reader never reads (section 6.5 step 3): a document read back carries null.
 */
final readonly class EntityDescriptor
{
    /**
     * @throws MalformedMessage when the entity ID is not a URI of M-6
     * @throws InvalidArgumentException when a role carries another entity ID, or the cacheDuration is under one second:
     *                                   a programming error of the caller
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
