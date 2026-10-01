<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Exception;

/**
 * A NameID that breaks the rule of its format: an unknown format, an empty value, whitespace around it, its length, a
 * qualifier its format forbids (M-12).
 */
final class InvalidNameId extends MessageRefused
{
}
