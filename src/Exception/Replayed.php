<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Exception;

/**
 * The assertion was accepted before: its ID is remembered under the entity ID of its issuer (M-11).
 */
final class Replayed extends MessageRefused
{
}
