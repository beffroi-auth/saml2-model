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
 * The assertion's side of the selection of the signed element, section 6.1 step 5 (M-1, M-2, M-4): the document the
 * assertion is read from. Its own ds:Signature, when it carries one, is verified on the one saml:Assertion child of
 * the received root, the element the response's signature covered when there is one, and never inside the response's
 * Verified::$document, whose re-parse holds only the declarations the response's exclusive form rendered: a PrefixList
 * naming a prefix declared above the assertion would lose it there. Without a signature of its own, the assertion is
 * read from the response's verification; with neither, the profile's requirement is not met (Profiles §4.1.4.5, E26).
 *
 * An assertion that arrived encrypted is the root of the document its decryption gave (section 6.7): its own signature
 * is verified there, and without one it is read from that document when the response's signature covered the
 * ciphertext, a decryption authenticating nothing (M-2).
 *
 * The position of the signature is checked on the received element, before it is verified: the verification removes
 * it from the document it hands over (D-10), where the reader could no longer see it out of its place (M-5).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class SignedAssertion
{
    /**
     * @param Document $document the document of the assertion's own verification, whose root is the assertion; of the
     *                           response's verification, whose root holds it; or of its decryption, whose root it is
     * @param bool $signed whether the assertion carries a signature of its own, verified here
     */
    private function __construct(
        public Document $document,
        public bool $signed,
    ) {
    }

    /**
     * @param Element $received the one saml:Assertion child of the received root (section 6.1 step 2)
     * @param SignedResponse $response what step 3 verified of the response
     * @param Loader $loader SamlLoader::create(), the Verifier's (M-14)
     *
     * @throws MalformedMessage when the assertion holds more than one ds:Signature, or one out of its place (M-4, M-5)
     * @throws SignatureRequired when neither the response nor the assertion is signed (M-2), or the metadata holds no
     *                           signing key (M-3)
     * @throws SignatureRefused one of its subclasses, when the assertion's signature does not verify
     * @throws RefusedXml what Core refuses of the re-parse (D-10)
     */
    public static function of(Element $received, SignedResponse $response, IdentityProvider $idp, Loader $loader): self
    {
        return self::select($received, $response->verification?->document, $idp, $loader);
    }

    /**
     * Section 6.7: the assertion a decryption gave, its own signature verified on the root of that document, or, without
     * one, the document itself when the response's signature covered the ciphertext.
     *
     * @param SignedResponse $response what step 3 verified of the response, whose ciphertext it covered when signed
     *
     * @throws MalformedMessage when the assertion holds more than one ds:Signature, or one out of its place (M-4, M-5)
     * @throws SignatureRequired when neither the response nor the assertion is signed (M-2), or the metadata holds no
     *                           signing key (M-3)
     * @throws SignatureRefused one of its subclasses, when the assertion's signature does not verify
     * @throws RefusedXml what Core refuses of the re-parse (D-10)
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
     * @param ?Document $covered the document the assertion is read from when it carries no signature, null when no
     *                           signature of the response covers it
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
        // the Signature follows the Issuer, the first child (SAML Core §2.3.3, §5.4.1)
        if ((Children::all($assertion)[1] ?? null) !== $signatures[0]) {
            throw new MalformedMessage('The saml:Assertion holds a child out of the order of the schema, or one it does not allow there (M-5).');
        }

        return new self(SignedResponse::verify($assertion, $idp, $loader)->document, true);
    }
}
