<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Response;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Xml\Core\Document;

/**
 * The plaintext of an encrypted assertion, section 6.7 step 4: the Document Enc loaded from the decryption, its root a
 * saml:Assertion (M-4). It holds the Document, so that the nodes of the decrypted assertion live as long as it is read
 * (enc.md section 5.4). Nothing here authenticates the assertion: anyone encrypts for the key of the service provider,
 * and section 6.1 step 5 asks for its signature or the response's (M-2).
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
     * @param Document $plaintext what Enc loaded of the decryption, with SamlLoader::create() (M-14)
     *
     * @throws MalformedMessage when the plaintext is not a saml:Assertion (M-4)
     */
    public static function of(Document $plaintext): self
    {
        if (! Schema::saml('Assertion')->matches($plaintext->root())) {
            throw new MalformedMessage('The plaintext of the saml:EncryptedAssertion is not a saml:Assertion (M-4).');
        }

        return new self($plaintext);
    }
}
