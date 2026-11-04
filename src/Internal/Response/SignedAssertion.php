<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Response;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Dsig\Exception\SignatureRefused;
use function count;
use Dom\Element;

/**
 * Section 6.1 step 5
 *
 * Its own signature is checked and verified on the received element: the response's re-parse may lack a prefix its
 * PrefixList names, and a verification removes the signature it verified (D-10).
 *
 * @internal
 */
final readonly class SignedAssertion
{
    private function __construct(
        public Document $document,
        public bool $signed,
    ) {
    }

    /**
     * @throws MalformedMessage
     * @throws SignatureRequired
     * @throws SignatureRefused
     * @throws RefusedXml
     */
    public static function of(Element $received, SignedResponse $response, IdentityProvider $idp, Loader $loader): self
    {
        return self::select($received, $response->verification?->document, $idp, $loader);
    }

    /**
     * Section 6.7
     *
     * @throws MalformedMessage
     * @throws SignatureRequired
     * @throws SignatureRefused
     * @throws RefusedXml
     */
    public static function decrypted(
        DecryptedAssertion $decrypted,
        SignedResponse $response,
        IdentityProvider $idp,
        Loader $loader,
    ): self {
        return self::select(
            $decrypted->document->root(),
            $response->verification === null ? null : $decrypted->document,
            $idp,
            $loader,
        );
    }

    /**
     * @param ?Document $covered null when no signature of the response covers the assertion
     *
     * @throws MalformedMessage
     * @throws SignatureRequired
     * @throws SignatureRefused
     * @throws RefusedXml
     */
    private static function select(Element $assertion, ?Document $covered, IdentityProvider $idp, Loader $loader): self
    {
        $signatures = Children::named($assertion, Schema::ds('Signature'));
        if (count($signatures) > 1) {
            throw new MalformedMessage('The saml:Assertion holds more than one ds:Signature (M-4).');
        }
        if ($signatures === []) {
            return new self(
                $covered ?? throw new SignatureRequired('Neither the response nor its assertion carries a ds:Signature, one of which the profile requires (M-2).'),
                false,
            );
        }
        // The Signature follows the Issuer, the first child (SAML Core §2.3.3, §5.4.1).
        if ((Children::all($assertion)[1] ?? null) !== $signatures[0]) {
            throw new MalformedMessage('The saml:Assertion holds a child out of the order of the schema, or one it does not allow there (M-5).');
        }

        return new self(SignedResponse::verify($assertion, $idp, $loader)->document, true);
    }
}
