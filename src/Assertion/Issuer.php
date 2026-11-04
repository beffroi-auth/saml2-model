<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Assertion;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Uri;

/**
 * SAML Core §2.2.5
 */
final readonly class Issuer
{
    /**
     * @throws MalformedMessage
     */
    public function __construct(
        public string $entityId,
    ) {
        Uri::read($entityId);
    }
}
