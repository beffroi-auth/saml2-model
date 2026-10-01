<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Protocol;

use Beffroi\Saml2\Model\Exception\MalformedMessage;

/**
 * The four top-level status codes of SAML Core §3.2.2.2, a closed vocabulary: the value of the topmost StatusCode
 * MUST be one of them, and fromUri() refuses every other URI (M-5).
 */
enum StatusCode: string
{
    case Success = 'urn:oasis:names:tc:SAML:2.0:status:Success';
    case Requester = 'urn:oasis:names:tc:SAML:2.0:status:Requester';
    case Responder = 'urn:oasis:names:tc:SAML:2.0:status:Responder';
    case VersionMismatch = 'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch';

    /**
     * @throws MalformedMessage for every other URI (M-5)
     */
    public static function fromUri(string $uri): self
    {
        return (
            self::tryFrom($uri) ?? throw new MalformedMessage('The top-level status code is not one of the four of SAML Core (M-5).')
        );
    }
}
