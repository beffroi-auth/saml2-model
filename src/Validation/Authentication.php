<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Validation;

/**
 * How a protocol message the validators accepted was authenticated (M-2).
 */
enum Authentication
{
    case XmlSignature;
    case Binding;
    case None;
}
