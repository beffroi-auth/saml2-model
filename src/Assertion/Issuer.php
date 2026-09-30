<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Assertion;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Uri;

/**
 * The saml:Issuer of a message or an assertion (SAML Core §2.2.5): an entity ID, a URI of M-6 (SAML Core §8.3.6). Its
 * Format is written omitted, and read omitted or entity (M-8, Profiles §4.1.4.1, §4.1.4.2, §4.4.4.1, §4.4.4.2); an
 * Issuer without Format is of format entity, never unspecified (SAML Core §2.2.5). Whether it is the peer's entity ID
 * is the validators' comparison (M-8).
 */
final readonly class Issuer
{
    /**
     * @throws MalformedMessage when the entity ID is not a URI of M-6
     */
    public function __construct(
        public string $entityId,
    ) {
        Uri::read($entityId);
    }
}
