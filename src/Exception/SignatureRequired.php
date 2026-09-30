<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Exception;

/**
 * No signature covers what the profile requires signed: an assertion covered by neither its own signature nor the
 * response's, a logout message without one, a request the metadata of either party asks to be signed; or the peer's
 * metadata holds no key to verify it (M-2, M-3).
 */
final class SignatureRequired extends MessageRefused
{
}
