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
 * Section 6.5
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
     * No ds:Signature is verified: the consumer trusts the channel the metadata came through (M-2).
     *
     * @throws MessageRefused
     * @throws RefusedXml
     */
    public function readTrusted(Document $document): EntityDescriptor
    {
        return EntityDescriptorReader::read($document->root(), $this->expired());
    }

    /**
     * M-1, M-2
     *
     * @throws SignatureRequired
     * @throws MessageRefused
     * @throws RefusedXml
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
     * Now minus the clock skew: a validUntil at or before it is past (M-7).
     */
    private function expired(): DateTimeImmutable
    {
        return new Window($this->clock->now(), $this->bounds)->earliest();
    }
}
