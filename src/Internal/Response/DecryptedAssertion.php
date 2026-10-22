<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Response;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Enc\DecryptionKeyInterface;
use Beffroi\Xml\Enc\Decryptor;
use Beffroi\Xml\Enc\Exception\DecryptionFailed;
use Beffroi\Xml\Enc\Exception\EncryptionRefused;

/**
 * The decryption of an encrypted assertion, section 6.7: the xenc:EncryptedData of the one saml:EncryptedAssertion of
 * the response as section 6.1 step 3 left it, the verified response when it is signed, so that the signature covered
 * the ciphertext before any decryption touches it, the received one otherwise; decrypted by Enc with the key of the
 * service provider and SamlLoader::create() (M-14), whose refusals pass as they are, every cryptographic failure the
 * one DecryptionFailed (E-3); the root of the plaintext a saml:Assertion (M-4). It holds the Document, so that the
 * nodes of the decrypted assertion live as long as it is read (enc.md section 5.4). Nothing here authenticates the
 * assertion: anyone encrypts for the key of the service provider, and section 6.1 step 5 asks for its signature or
 * the response's (M-2).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class DecryptedAssertion
{
    private function __construct(
        public Document $document,
    ) {
    }

    /**
     * @param SignedResponse $response what section 6.1 step 3 verified of a response whose envelope holds a
     *                                 saml:EncryptedAssertion (step 2)
     * @param DecryptionKeyInterface $key the service provider's (section 5.5)
     * @param Loader $loader SamlLoader::create(), which loads the plaintext (M-14, E-4)
     *
     * @throws DecryptionFailed the one failure of every cryptographic step (E-3)
     * @throws EncryptionRefused the other refusals of Enc, naming their rule (E-1, E-5, E-13)
     * @throws MalformedMessage when the plaintext is not a saml:Assertion (M-4)
     * @throws RefusedXml what Core refuses of the plaintext (E-4)
     */
    public static function of(SignedResponse $response, DecryptionKeyInterface $key, Loader $loader): self
    {
        $document = new Decryptor($loader)->decrypt(
            Children::one(
                Children::one($response->root, Schema::saml('EncryptedAssertion')),
                Schema::xenc('EncryptedData'),
            ),
            $key,
        );
        if (! Schema::saml('Assertion')->matches($document->root())) {
            throw new MalformedMessage('The plaintext of the saml:EncryptedAssertion is not a saml:Assertion (M-4).');
        }

        return new self($document);
    }
}
