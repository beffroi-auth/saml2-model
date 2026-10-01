<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Exception;

/**
 * The assertion consumer service or the single logout service a message names, by URL or by index, is not one the
 * metadata of the peer lists (M-9).
 */
final class UnknownEndpoint extends MessageRefused
{
}
