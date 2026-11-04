<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Response;

use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Dsig\Exception\SignatureRefused;
use Beffroi\Xml\Dsig\Verified;
use Beffroi\Xml\Dsig\Verifier;
use Dom\Element;

/**
 * Section 6.1 step 3
 *
 * Verified with the keys of the identity provider's metadata, never with the message's KeyInfo (D-7).
 * It holds the Verified, so that the document of the verification lives as long as its root is read.
 *
 * @internal
 */
final readonly class SignedResponse
{
    private function __construct(
        public Element $root,
        public ?Verified $verification,
    ) {
    }

    /**
     * @throws SignatureRequired when the response is signed and the metadata holds no signing key
     * @throws SignatureRefused
     * @throws RefusedXml
     */
    public static function of(Element $received, IdentityProvider $idp, Loader $loader): self
    {
        if (Children::named($received, Schema::ds('Signature')) === []) {
            return new self($received, null);
        }
        $verification = self::verify($received, $idp, $loader);

        return new self($verification->document->root(), $verification);
    }

    /**
     * @throws SignatureRequired when the metadata holds no signing key
     * @throws SignatureRefused
     * @throws RefusedXml
     */
    public static function verify(Element $signed, IdentityProvider $idp, Loader $loader): Verified
    {
        return new Verifier($loader)->verify(
            $signed,
            $idp->verificationKeys() ?? throw new SignatureRequired('The metadata of the peer holds no signing key to verify the message with (M-3).'),
        );
    }
}
