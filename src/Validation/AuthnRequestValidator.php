<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Validation;

use Beffroi\Saml2\Model\Exception\MessageRefused;
use Beffroi\Saml2\Model\Internal\AuthnRequest\AuthnRequestContext;
use Beffroi\Saml2\Model\Internal\AuthnRequest\AuthnRequestReader;
use Beffroi\Saml2\Model\Internal\Protocol\MessageAuthentication;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\UnverifiedAuthnRequest;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/**
 * An AuthnRequest, identity provider side, in the order of section 6.2 (section 5.6): the structure of the request
 * as it arrived; the signature the metadata of either party asks for, and every signature present (M-2), verified
 * under the service provider's keys (M-3); the header against the clock, read once (M-7), and against the URL of
 * arrival (M-8); the assertion consumer service of the service provider's metadata (M-9); what the request asks,
 * returned. A request this refuses gets no SAML answer: its endpoint is not established, and an answer sent where
 * the request says would be the theft M-9 closes.
 */
final readonly class AuthnRequestValidator
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
     * The request as it arrived over HTTP-POST, or over HTTP-Redirect without a signature: a ds:Signature child is
     * verified with $sp's keys (M-2); none is accepted only when neither $sp nor $self asks for signed requests
     * (Profiles §4.1.6).
     *
     * @param ServiceProvider $sp the service provider the consumer chose with UnverifiedAuthnRequest::$issuer
     * @param IdentityProvider $self our own role, its single sign-on services and whether it wants requests signed
     * @param string $receivedAt the URL of our SingleSignOnService at which the request arrived
     *
     * @throws MessageRefused one of its subclasses, naming the rule (M-16)
     * @throws RefusedXml what Core and Dsig refuse, as they refuse it
     */
    public function validate(
        UnverifiedAuthnRequest $request,
        ServiceProvider $sp,
        IdentityProvider $self,
        string $receivedAt,
    ): AcceptedAuthnRequest {
        $now = $this->clock->now();
        AuthnRequestReader::structure($request->document->root());
        $authentication = $sp->authnRequestsSigned || $self->wantAuthnRequestsSigned
            ? MessageAuthentication::signatureRequired($request->document, $sp->verificationKeys(), $this->loader)
            : MessageAuthentication::signatureOptional($request->document, $sp->verificationKeys(), $this->loader);

        return $this->accept($authentication, $now, $sp, $self, $receivedAt);
    }

    /**
     * The request as it arrived over HTTP-Redirect with a signature over its query string, which saml2-bindings
     * verified with Verifier::verifyDetached() under $sp's keys before calling: the caller asserts it. A ds:Signature
     * child is refused (SAML Bindings §3.4.4.1 removes it before encoding).
     *
     * @param ServiceProvider $sp the service provider whose keys verified the query string
     * @param IdentityProvider $self our own role, its single sign-on services
     * @param string $receivedAt the URL of our SingleSignOnService at which the request arrived
     *
     * @throws MessageRefused one of its subclasses, naming the rule (M-16)
     * @throws RefusedXml what Core refuses, as it refuses it
     */
    public function validateAuthenticatedByBinding(
        UnverifiedAuthnRequest $request,
        ServiceProvider $sp,
        IdentityProvider $self,
        string $receivedAt,
    ): AcceptedAuthnRequest {
        $now = $this->clock->now();
        AuthnRequestReader::structure($request->document->root());

        return $this->accept(MessageAuthentication::byBinding($request->document), $now, $sp, $self, $receivedAt);
    }

    /**
     * Section 6.2 steps 3 to 6, on the document the authentication handed over (M-1).
     *
     * @throws MessageRefused
     * @throws RefusedXml
     */
    private function accept(
        MessageAuthentication $authentication,
        DateTimeImmutable $now,
        ServiceProvider $sp,
        IdentityProvider $self,
        string $receivedAt,
    ): AcceptedAuthnRequest {
        [$request, $assertionConsumerService] = AuthnRequestReader::read(
            $authentication->document->root(),
            new AuthnRequestContext(
                $now,
                $this->bounds,
                $sp,
                $self,
                $receivedAt,
                $authentication->authentication,
            ),
        );

        return new AcceptedAuthnRequest($request, $assertionConsumerService, $authentication->authentication);
    }
}
