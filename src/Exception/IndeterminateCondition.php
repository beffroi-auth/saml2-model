<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Exception;

/**
 * A condition the package does not understand makes the assertion Indeterminate, which is refused like an Invalid
 * one (M-13, SAML Core §2.5.1.1).
 */
final class IndeterminateCondition extends MessageRefused
{
}
