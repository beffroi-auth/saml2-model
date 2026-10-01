<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Exception;

/**
 * InResponseTo does not name the request the consumer expects an answer to, is absent from an answer, or is present
 * on an unsolicited response (M-10).
 */
final class InResponseToMismatch extends MessageRefused
{
}
