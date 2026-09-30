<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Metadata;

use Beffroi\Saml2\Model\Exception\MessageRefused;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Internal\Metadata\EntityDescriptorReader;
use Beffroi\Saml2\Model\Internal\Window;
use Beffroi\Saml2\Model\Validation\TimeBounds;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Dsig\Verifier;
use DateTimeImmutable;
use Dom\Element;
use Psr\Clock\ClockInterface;

/**
 * A peer's md:EntityDescriptor read strictly, in the order of section 6.5 (section 5.6): where its keys come from
 * (M-3) and where an assertion may go (M-9). readTrusted() reads metadata the consumer trusts by its channel without
 * verifying a signature, the one exception of M-2, named; readSigned() verifies it with keys the consumer pinned and
 * reads what the signature covered (M-1). The clock is read once per call (M-7).
 */
final readonly class MetadataReader
{
    /**
     * @param Loader $loader SamlLoader::create(), the Verifier's too (M-14)
     */
    public function __construct(
        private Loader $loader,
        private ClockInterface $clock,
        private TimeBounds $bounds = new TimeBounds(),
    ) {
    }

    /**
     * Metadata the consumer trusts by the channel it came through (an administrator's upload, a pinned URL over
     * TLS): a ds:Signature is not verified here, the consumer said why.
     *
     * @throws MessageRefused one of its subclasses, naming the rule (M-16)
     * @throws RefusedXml what Core and Dsig refuse, as they refuse it
     */
    public function readTrusted(Document $document): EntityDescriptor
    {
        return EntityDescriptorReader::read($document->root(), $this->expired());
    }

    /**
     * Metadata signed by a key the consumer pinned: the ds:Signature, the first child of the root, is verified (M-2),
     * and the descriptor read from Verified::$document (M-1).
     *
     * @throws SignatureRequired when the root carries no ds:Signature (M-2)
     * @throws MessageRefused one of its subclasses, naming the rule (M-16)
     * @throws RefusedXml what Core and Dsig refuse, as they refuse it
     */
    public function readSigned(Document $document, VerificationKeys $keys): EntityDescriptor
    {
        $expired = $this->expired();
        $root = $document->root();
        if (! EntityDescriptorReader::signature($root) instanceof Element) {
            throw new SignatureRequired('The metadata carries no ds:Signature as the first child of its root (M-2).');
        }

        return EntityDescriptorReader::read(
            new Verifier($this->loader)->verify($root, $keys)->document->root(),
            $expired,
        );
    }

    /**
     * Now minus the clock skew, now read once: a validUntil at or before it is past (M-7).
     */
    private function expired(): DateTimeImmutable
    {
        return new Window($this->clock->now(), $this->bounds)->earliest();
    }
}
