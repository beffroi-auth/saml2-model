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
 * A response of the Web Browser SSO profile, service provider side, in the order of section 6.1: the structure of the
 * envelope before any key is touched (M-4), the response's signature whatever the status, a failure yielding
 * UnsuccessfulResponse (M-13), the assertion's signature verified on the one assertion child of the received root and
 * the assertion read from what a signature covered only (M-1, M-2), the envelope (M-7, M-8, M-10), the rules of the
 * assertion (M-5 to M-8, M-10, M-12, M-13, M-17), and replay last (M-11), so that nothing is remembered of a message a
 * rule refused. An encrypted assertion is decrypted with the key given with the identity provider, the one whose
 * certificate went to the provider whose metadata verify the response (section 5.5), once the response's signature
 * covered its ciphertext and the envelope passed, then verified on the root of its decryption and read inside the
 * decryption (section 6.7). The keys are the identity provider's metadata ones (M-3); the refusals of Core, Dsig and
 * Enc pass as they are, every failure of a decryption Enc's one DecryptionFailed (E-3), and under AES-CBC every
 * refusal of the reading after it (E-16).
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
     * @param IdentityProvider $idp the provider the consumer chose, given the service provider's key whose encryption
     *                              certificate went to it when it encrypts (section 5.5)
     *
     * @throws MessageRefused one of its subclasses, naming the rule (M-16)
     * @throws RefusedXml what Core, Dsig and Enc refuse, as they refuse it
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
        // 1 and 2: the root, checked by UnverifiedResponse::of(); the structure of the envelope, no key touched yet
        $received = $response->document->root();
        $envelope = Envelope::of($received);
        $assertion = $envelope->assertion;
        // the key of an encrypted assertion, the one given with the provider whose metadata verify the response: a
        // provider given none is refused now, before any key is touched; the reader reads it again from the provider
        // (section 5.5)
        if ($envelope->encrypted) {
            PlaintextReader::keyOf($idp);
        }
        // 3: the response's signature, whatever the status; the response read from its verification from here on
        $signedResponse = SignedResponse::of($received, $idp, $this->loader);
        // 4: a failure, after the envelope rules
        if (! $assertion instanceof Element) {
            EnvelopeReader::read($signedResponse, $context);

            throw new UnsuccessfulResponse(Envelope::of($signedResponse->root)->status);
        }
        if ($envelope->encrypted) {
            // section 6.7: the envelope of step 6 first, which needs nothing of the plaintext, so that a response it
            // refuses costs no operation of the key; then the decryption, from what step 3 verified, and steps 5 and 7
            // to 12 on the root of the decrypted document, inside the decryption (E-16)
            $responseId = EnvelopeReader::read($signedResponse, $context);
            $read = PlaintextReader::decrypt($signedResponse, $idp, $this->loader, $context);
        } else {
            // 5: the assertion's signature, on the assertion child of the received root, or the response's
            $signedAssertion = SignedAssertion::of($assertion, $signedResponse, $idp, $this->loader);
            // 6: the envelope
            $responseId = EnvelopeReader::read($signedResponse, $context);
            // 7 to 12: the assertion, from the document a signature covered (M-1)
            $read = new ReadAssertion(AssertionReader::readCovered($signedAssertion, $context), $signedAssertion->signed);
        }
        $accepted = $read->assertion;
        // 13: replay, last, with the verified values (M-11)
        $remembered = $this->replay->remember(
            $accepted->issuer->entityId,
            $accepted->id,
            $accepted->confirmation->notOnOrAfter->modify(sprintf('+%d seconds', $this->bounds->clockSkew)),
        );
        if (! $remembered) {
            throw new Replayed('The assertion was already accepted from its issuer (M-11).');
        }

        // 14: the result, its values copied out of the verified documents, and whether step 2 found the assertion
        // encrypted (M-18)
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
