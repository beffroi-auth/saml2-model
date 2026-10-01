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
 * the entity ID of its descriptor.
 */
final readonly class EntityDescriptor
{
    /**
     * @throws MalformedMessage when the entity ID is not a URI of M-6
     * @throws InvalidArgumentException when a role carries another entity ID: a programming error of the caller
     */
    public function __construct(
        public string $entityId,
        public ?DateTimeImmutable $validUntil = null,
        public ?IdentityProvider $identityProvider = null,
        public ?ServiceProvider $serviceProvider = null,
    ) {
        Uri::read($entityId);
        if ($identityProvider instanceof IdentityProvider && $identityProvider->entityId !== $entityId) {
            throw new InvalidArgumentException('The identity provider carries the entity ID of its descriptor (section 5.3).');
        }
        if ($serviceProvider instanceof ServiceProvider && $serviceProvider->entityId !== $entityId) {
            throw new InvalidArgumentException('The service provider carries the entity ID of its descriptor (section 5.3).');
        }
    }
}
