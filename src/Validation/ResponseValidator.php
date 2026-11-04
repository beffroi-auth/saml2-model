<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Validation;

use Dom\Element;
use Beffroi\Xml\Dsig\Verified;
use Beffroi\Saml2\Model\Exception\MessageRefused;
use Beffroi\Saml2\Model\Exception\Replayed;
use Beffroi\Saml2\Model\Exception\UnsuccessfulResponse;
use Beffroi\Saml2\Model\Internal\Assertion\AssertionContext;
use Beffroi\Saml2\Model\Internal\Assertion\AssertionReader;
use Beffroi\Saml2\Model\Internal\Response\PlaintextReader;
use Beffroi\Saml2\Model\Internal\Response\Envelope;
use Beffroi\Saml2\Model\Internal\Response\EnvelopeReader;
use Beffroi\Saml2\Model\Internal\Response\ReadAssertion;
use Beffroi\Saml2\Model\Internal\Response\SignedAssertion;
use Beffroi\Saml2\Model\Internal\Response\SignedResponse;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Port\ReplayGuardInterface;
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use Psr\Clock\ClockInterface;
use function sprintf;

/**
 * Sections 6.1 and 6.7
 */
final readonly class ResponseValidator
{
    /**
     * @param Loader $loader SamlLoader::create(), the Verifier's and the Decryptor's too (M-14)
     */
    public function __construct(
        private Loader $loader,
        private ClockInterface $clock,
        private ReplayGuardInterface $replay,
        private TimeBounds $bounds = new TimeBounds(),
    ) {
    }

    /**
     * @throws MessageRefused
     * @throws RefusedXml
     */
    public function validate(
        UnverifiedResponse $response,
        IdentityProvider $idp,
        ExpectedResponse $expected,
    ): AcceptedAssertion {
        $context = new AssertionContext(
            $this->clock->now(),
            $this->bounds,
            $idp->entityId,
            $expected->audience,
            $expected->receivedAt,
            $expected->requestId,
        );
        $received = $response->document->root();
        $envelope = Envelope::of($received);
        $assertion = $envelope->assertion;
        // A provider given no decryption key is refused now, before any key is touched (section 5.5).
        if ($envelope->encrypted) {
            PlaintextReader::keyOf($idp);
        }
        // The response's signature is verified whatever the status (M-13).
        $signedResponse = SignedResponse::of($received, $idp, $this->loader);
        // A failure is reported only once the envelope rules passed.
        if (! $assertion instanceof Element) {
            EnvelopeReader::read($signedResponse, $context);

            throw new UnsuccessfulResponse(Envelope::of($signedResponse->root)->status);
        }
        if ($envelope->encrypted) {
            // The envelope first, which needs nothing of the plaintext, so that a response it refuses costs no
            // operation of the key (section 6.7).
            $responseId = EnvelopeReader::read($signedResponse, $context);
            $read = PlaintextReader::decrypt($signedResponse, $idp, $this->loader, $context);
        } else {
            $signedAssertion = SignedAssertion::of($assertion, $signedResponse, $idp, $this->loader);
            $responseId = EnvelopeReader::read($signedResponse, $context);
            $read = new ReadAssertion(AssertionReader::readCovered($signedAssertion, $context), $signedAssertion->signed);
        }
        $accepted = $read->assertion;
        // Replay last, on the verified values: nothing is remembered of a message a rule refused (M-11).
        $remembered = $this->replay->remember(
            $accepted->issuer->entityId,
            $accepted->id,
            $accepted->confirmation->notOnOrAfter->modify(sprintf('+%d seconds', $this->bounds->clockSkew)),
        );
        if (! $remembered) {
            throw new Replayed('The assertion was already accepted from its issuer (M-11).');
        }

        return new AcceptedAssertion($responseId, $accepted, $this->coverage($signedResponse, $read), $envelope->encrypted);
    }

    private function coverage(SignedResponse $response, ReadAssertion $assertion): SignatureCoverage
    {
        if (! $response->verification instanceof Verified) {
            return SignatureCoverage::Assertion;
        }

        return $assertion->signed ? SignatureCoverage::AssertionAndResponse : SignatureCoverage::Response;
    }
}
