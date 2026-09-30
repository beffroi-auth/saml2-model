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
 * The response's side of the selection of the signed element, section 6.1 step 3 (M-1, M-2, M-3): the ds:Signature a
 * direct child of the received root, when there is one, verified whatever the status with the keys of the identity
 * provider's metadata and never with the message's KeyInfo (D-7), and the response read from Verified::$document from
 * then on. It holds the Verified, so that the document of the verification lives as long as its root is read.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class SignedResponse
{
    /**
     * @param Element $root the root of Verified::$document, or the received root when the response is not signed
     * @param ?Verified $verification the verification of the response's signature, null when it carries none
     */
    private function __construct(
        public Element $root,
        public ?Verified $verification,
    ) {
    }

    /**
     * @param Element $received the root of the received document, its structure checked (section 6.1 step 2)
     * @param Loader $loader SamlLoader::create(), the Verifier's (M-14)
     *
     * @throws SignatureRequired when the response is signed and the metadata holds no signing key (M-3)
     * @throws SignatureRefused one of its subclasses, when the signature does not verify
     * @throws RefusedXml what Core refuses of the re-parse (D-10)
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
     * The signature of $signed, its direct child, verified with the keys of the identity provider's metadata (M-3).
     *
     * @throws SignatureRequired when the metadata holds no signing key (M-3)
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
