<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Response;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Xml\Core\Document;

/**
 * Section 6.7 step 4
 *
 * It holds the Document, so that the nodes of the assertion live as long as it is read (enc.md section 5.4).
 * A decryption authenticates nothing: anyone can encrypt for the key of the service provider (M-2).
 *
 * @internal
 */
final readonly class DecryptedAssertion
{
    private function __construct(
        public Document $document,
    ) {
    }

    /**
     * @throws MalformedMessage
     */
    public static function of(Document $plaintext): self
    {
        if (! Schema::saml('Assertion')->matches($plaintext->root())) {
            throw new MalformedMessage('The plaintext of the saml:EncryptedAssertion is not a saml:Assertion (M-4).');
        }

        return new self($plaintext);
    }
}
