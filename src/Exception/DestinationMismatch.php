<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Exception;

/**
 * The Destination of a message is not the URL at which it arrived, compared byte for byte, or is absent from a signed
 * message (M-8).
 */
final class DestinationMismatch extends MessageRefused
{
}
