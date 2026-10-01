<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Protocol;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Dsig\Exception\SignatureRefused;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Dsig\Verifier;
use function count;

/**
 * The rule of M-2 for a received protocol message, an AuthnRequest, a LogoutRequest or a LogoutResponse (section
 * 5.6): the document to read the message from, and how it was authenticated. A ds:Signature is looked for as a direct
 * child of the root and nowhere else (M-4, I-11); when there is one, it is verified with the keys of the peer's
 * metadata (M-3) and the message is read from Verified::$document (M-1). Dsig's refusals pass through as they are
 * (section 5.8).
 *
 * @internal
 */
final readonly class MessageAuthentication
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    private function __construct(
        public Document $document,
        public Authentication $authentication,
    ) {
    }

    /**
     * The validate() path of a message the profile requires signed, a LogoutRequest, a LogoutResponse, or an
     * AuthnRequest the metadata of either party asks to be signed (Profiles §4.1.6, §4.4.4.1, §4.4.4.2).
     *
     * @param ?VerificationKeys $keys the keys of the peer's metadata, null when it holds no signing certificate
     * @param Loader $loader SamlLoader::create(), the Verifier's (M-14)
     *
     * @throws SignatureRequired when the peer has no signing key (M-3), or the message carries no ds:Signature (M-2)
     * @throws MalformedMessage when the root holds more than one ds:Signature (M-5)
     * @throws SignatureRefused one of its subclasses, when the signature does not verify
     * @throws RefusedXml what Core refuses of the re-parse (D-10)
     */
    public static function signatureRequired(Document $received, ?VerificationKeys $keys, Loader $loader): self
    {
        if (self::signature($received) === 0) {
            throw $keys instanceof VerificationKeys
                ? new SignatureRequired('The message carries no ds:Signature, which the profile requires (M-2).')
                : self::noKey();
        }

        return self::verified($received, $keys, $loader);
    }

    /**
     * The validate() path of an AuthnRequest that neither party's metadata asks to be signed (Profiles §4.1.6): a
     * ds:Signature, when present, is verified all the same (M-2); without one, the message was authenticated by
     * nothing.
     *
     * @param ?VerificationKeys $keys the keys of the peer's metadata, null when it holds no signing certificate
     * @param Loader $loader SamlLoader::create(), the Verifier's (M-14)
     *
     * @throws SignatureRequired when the message carries a ds:Signature and the peer has no signing key (M-3)
     * @throws MalformedMessage when the root holds more than one ds:Signature (M-5)
     * @throws SignatureRefused one of its subclasses, when the signature does not verify
     * @throws RefusedXml what Core refuses of the re-parse (D-10)
     */
    public static function signatureOptional(Document $received, ?VerificationKeys $keys, Loader $loader): self
    {
        if (self::signature($received) === 0) {
            return new self($received, Authentication::None);
        }

        return self::verified($received, $keys, $loader);
    }

    /**
     * The validateAuthenticatedByBinding() path: saml2-bindings verified the signature over the query string of
     * HTTP-Redirect, whose encoding removes the ds:Signature of the message (SAML Bindings §3.4.4.1).
     *
     * @throws MalformedMessage when the root holds a ds:Signature
     */
    public static function byBinding(Document $received): self
    {
        if (self::signature($received) !== 0) {
            throw new MalformedMessage('The message carries a ds:Signature, which the HTTP-Redirect encoding removes (SAML Bindings §3.4.4.1).');
        }

        return new self($received, Authentication::Binding);
    }

    /**
     * How many ds:Signature the root holds as direct children, zero or one.
     *
     * @throws MalformedMessage when it holds more than one (M-5)
     */
    private static function signature(Document $received): int
    {
        $signatures = count(Children::named($received->root(), new Name(self::DSIG, 'Signature')));
        if ($signatures > 1) {
            throw new MalformedMessage('The message holds more than one ds:Signature as a direct child of its root (M-5).');
        }

        return $signatures;
    }

    /**
     * @throws SignatureRequired
     * @throws SignatureRefused
     * @throws RefusedXml
     */
    private static function verified(Document $received, ?VerificationKeys $keys, Loader $loader): self
    {
        if (! $keys instanceof VerificationKeys) {
            throw self::noKey();
        }

        return new self(
            new Verifier($loader)->verify($received->root(), $keys)->document,
            Authentication::XmlSignature,
        );
    }

    private static function noKey(): SignatureRequired
    {
        return new SignatureRequired('The metadata of the peer holds no signing key to verify the message with (M-3).');
    }
}
