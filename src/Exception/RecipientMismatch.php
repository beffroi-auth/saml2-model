<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Exception;

/**
 * The Recipient of the bearer confirmation is not the URL at which the response arrived, compared byte for byte (M-8).
 */
final class RecipientMismatch extends MessageRefused
{
}
