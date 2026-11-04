<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Response;

use Beffroi\Saml2\Model\Exception\MessageRefused;
use Beffroi\Saml2\Model\Exception\Unsupported;
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
 * Section 6.7 steps 3 to 5
 *
 * The plaintext is read inside the decryption, so that under AES-CBC every refusal of its reading is Enc's one
 * DecryptionFailed (E-16).
 *
 * @internal
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
     * @throws Unsupported when the provider was given no key
     */
    public static function keyOf(IdentityProvider $idp): DecryptionKeyInterface
    {
        return (
            $idp->decryptionKey ?? throw new Unsupported('The response holds a saml:EncryptedAssertion and the identity provider was given no key to decrypt it (section 6.7).')
        );
    }

    /**
     * @param SignedResponse $response its envelope already read (section 6.1 step 6)
     *
     * @throws Unsupported when the provider was given no key
     * @throws MessageRefused
     * @throws EncryptionRefused
     * @throws RefusedXml
     */
    public static function decrypt(
        SignedResponse $response,
        IdentityProvider $idp,
        Loader $loader,
        AssertionContext $context,
    ): ReadAssertion {
        $key = self::keyOf($idp);
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
     * Section 6.7 steps 4 and 5
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
