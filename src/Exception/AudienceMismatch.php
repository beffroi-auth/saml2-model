<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Exception;

/**
 * An AudienceRestriction of the assertion does not hold our entity ID, or the assertion has none (M-8, SAML Core
 * §2.5.1.4 as corrected by erratum E46).
 */
final class AudienceMismatch extends MessageRefused
{
}
