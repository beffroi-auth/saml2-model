<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Response;

use Beffroi\Saml2\Model\Exception\MessageRefused;
use Beffroi\Saml2\Model\Internal\Assertion\AssertionContext;
use Beffroi\Saml2\Model\Internal\Assertion\AssertionReader;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Dsig\Verified;
use Beffroi\Xml\Enc\DecryptionKeyInterface;
use Beffroi\Xml\Enc\Decryptor;
use Beffroi\Xml\Enc\Exception\EncryptionRefused;
use Beffroi\Xml\Enc\PlaintextReaderInterface;

/**
 * The decryption of an encrypted assertion and its reading, section 6.7 steps 3 to 5: the xenc:EncryptedData of the
 * one saml:EncryptedAssertion of the response as section 6.1 step 3 left it, the verified response when it is signed,
 * so that the signature covered the ciphertext before any decryption touches it, the received one otherwise; decrypted
 * by Enc with the key given with the identity provider whose metadata verified the response (section 5.5, enc.md
 * E-15) and SamlLoader::create() (M-14), under the proof of the response's signature when there is one, which alone
 * opens AES-CBC, and without proof otherwise, AES-CBC then refused by name before any key is touched. The plaintext is
 * read here, steps 4 and 5 then 7 to 12, inside the decryption when the response is signed: under AES-CBC, every
 * refusal of that reading is Enc's one DecryptionFailed, raised from the one place of the decryptor (E-16); under
 * AES-GCM, each passes as it is.
 *
 * @internal outside the compatibility promise of section 5
 *
 * @implements PlaintextReaderInterface<ReadAssertion>
 */
final readonly class PlaintextReader implements PlaintextReaderInterface
{
    private function __construct(
        private SignedResponse $response,
        private IdentityProvider $idp,
        private Loader $loader,
        private AssertionContext $context,
    ) {
    }

    /**
     * @param SignedResponse $response what section 6.1 step 3 verified of a response whose envelope holds a
     *                                 saml:EncryptedAssertion (step 2), its envelope read (step 6)
     * @param IdentityProvider $idp the provider whose metadata verified the response
     * @param DecryptionKeyInterface $key the key given with $idp (section 5.5)
     * @param Loader $loader SamlLoader::create(), which loads the plaintext and verifies its signature (M-14, E-4)
     *
     * @throws MessageRefused what the reading of the assertion refuses, under AES-GCM
     * @throws EncryptionRefused the refusals of Enc, naming their rule (E-1, E-5, E-13, E-15), or its one failure (E-3,
     *                           E-16)
     * @throws RefusedXml what Core and Dsig refuse of an AES-GCM plaintext (E-4)
     */
    public static function decrypt(
        SignedResponse $response,
        IdentityProvider $idp,
        DecryptionKeyInterface $key,
        Loader $loader,
        AssertionContext $context,
    ): ReadAssertion {
        $encrypted = Children::one(
            Children::one($response->root, Schema::saml('EncryptedAssertion')),
            Schema::xenc('EncryptedData'),
        );
        $reader = new self($response, $idp, $loader, $context);
        $decryptor = new Decryptor($loader);
        if ($response->verification instanceof Verified) {
            return $decryptor->decryptCovered(
                $encrypted,
                $key,
                new CoveringResponseSignature($response->verification),
                $reader,
            );
        }

        return $reader->read($decryptor->decrypt($encrypted, $key));
    }

    /**
     * Section 6.7 steps 4 and 5: the plaintext a saml:Assertion (M-4), its own signature verified on its root or the
     * response's over its ciphertext (M-2), and steps 7 to 12 of section 6.1 on what a signature covered (M-1).
     *
     * @throws MessageRefused
     * @throws RefusedXml
     */
    public function read(Document $plaintext): ReadAssertion
    {
        $assertion = SignedAssertion::decrypted(
            DecryptedAssertion::of($plaintext),
            $this->response,
            $this->idp,
            $this->loader,
        );

        return new ReadAssertion(AssertionReader::readCovered($assertion, $this->context), $assertion->signed);
    }
}
