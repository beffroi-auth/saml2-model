<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Exception;

/**
 * A time outside its window, the window named in the message: NotBefore, NotOnOrAfter, SessionNotOnOrAfter,
 * validUntil, IssueInstant, the age of the message or the length of the bearer window (M-7).
 */
final class OutsideValidityWindow extends MessageRefused
{
}
