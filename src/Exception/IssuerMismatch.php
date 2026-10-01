<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Exception;

/**
 * The Issuer of a message or of an assertion is not the entity ID of the peer, or its Format is neither omitted nor
 * entity (M-8).
 */
final class IssuerMismatch extends MessageRefused
{
}
