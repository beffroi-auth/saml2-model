<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Exception;

/**
 * The structure or a lexical form of the message: a child missing, out of order or of an element the schema does not
 * allow there, a second occurrence of an element allowed once, a value not in its one lexical form, a URI outside a
 * closed vocabulary (M-4, M-5, M-6).
 */
final class MalformedMessage extends MessageRefused
{
}
