<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Exception;

use Beffroi\Xml\Core\Exception\RefusedXml;

/**
 * Its message names the rule, never a value of the input (M-16).
 */
abstract class MessageRefused extends RefusedXml
{
}
