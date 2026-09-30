<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Exception;

use Beffroi\Xml\Core\Exception\RefusedXml;

/**
 * A message, an assertion or a metadata document the package refuses (section 5.8). It extends the RefusedXml of
 * Core, as the refusals of Dsig and Enc do, so that a consumer that catches that base class catches everything the
 * stack refuses. Its message names the rule in parentheses, (M-8) or (section 8), and never carries a value of the
 * input: no ID, no NameID, no entity ID, no URL, no attribute value, no status message (M-16).
 */
abstract class MessageRefused extends RefusedXml
{
}
