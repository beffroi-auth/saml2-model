<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Exception;

/**
 * What SAML allows and the package refuses by name, as section 8 lists it.
 */
final class Unsupported extends MessageRefused
{
}
