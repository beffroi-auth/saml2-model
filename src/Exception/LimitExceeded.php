<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Exception;

/**
 * A count or a length over its bound of section 7, the bound named in the message (M-17).
 */
final class LimitExceeded extends MessageRefused
{
}
