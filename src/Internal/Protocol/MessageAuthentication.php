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
 * M-2
 *
 * A ds:Signature is looked for as a direct child of the root and nowhere else (I-11).
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
     * SAML Profiles §4.1.6, §4.4.4.1, §4.4.4.2
     *
     * @throws SignatureRequired
     * @throws MalformedMessage
     * @throws SignatureRefused
     * @throws RefusedXml
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
     * SAML Profiles §4.1.6
     *
     * A ds:Signature, when present, is verified all the same (M-2).
     *
     * @throws SignatureRequired when the message is signed and the peer has no signing key
     * @throws MalformedMessage
     * @throws SignatureRefused
     * @throws RefusedXml
     */
    public static function signatureOptional(Document $received, ?VerificationKeys $keys, Loader $loader): self
    {
        if (self::signature($received) === 0) {
            return new self($received, Authentication::None);
        }

        return self::verified($received, $keys, $loader);
    }

    /**
     * A peer whose metadata holds no key cannot have been verified by the binding, and is refused (M-3).
     *
     * @throws MalformedMessage when the root holds a ds:Signature
     * @throws SignatureRequired
     */
    public static function byBinding(Document $received, ?VerificationKeys $keys): self
    {
        if (self::signature($received) !== 0) {
            throw new MalformedMessage('The message carries a ds:Signature, which the HTTP-Redirect encoding removes (SAML Bindings §3.4.4.1).');
        }
        if (! $keys instanceof VerificationKeys) {
            throw self::noKey();
        }

        return new self($received, Authentication::Binding);
    }

    /**
     * @throws MalformedMessage
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
