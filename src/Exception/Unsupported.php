<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Exception;

/**
 * What SAML allows and the package refuses by name, each listed in section 8: saml:Advice, saml:ProxyRestriction, a
 * confirmation method other than bearer, md:EntitiesDescriptor, saml:EncryptedID and saml:EncryptedAttribute, an
 * encrypted assertion the validator holds no key for, and the rest of that list.
 */
final class Unsupported extends MessageRefused
{
}
