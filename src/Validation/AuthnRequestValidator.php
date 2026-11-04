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
 * Section 6.2
 *
 * A request this refuses gets no SAML answer: its endpoint is not established (M-9).
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
     * SAML Profiles §4.1.6, M-2
     *
     * @param string $receivedAt the URL of our SingleSignOnService at which the request arrived
     *
     * @throws MessageRefused
     * @throws RefusedXml
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
     * The caller asserts that saml2-bindings verified the signature over the query string under $sp's keys; a
     * ds:Signature child is refused (SAML Bindings §3.4.4.1).
     *
     * @param string $receivedAt the URL of our SingleSignOnService at which the request arrived
     *
     * @throws MessageRefused
     * @throws RefusedXml
     */
    public function validateAuthenticatedByBinding(
        UnverifiedAuthnRequest $request,
        ServiceProvider $sp,
        IdentityProvider $self,
        string $receivedAt,
    ): AcceptedAuthnRequest {
        $now = $this->clock->now();
        AuthnRequestReader::structure($request->document->root());

        return $this->accept(
            MessageAuthentication::byBinding($request->document, $sp->verificationKeys()),
            $now,
            $sp,
            $self,
            $receivedAt,
        );
    }

    /**
     * Section 6.2 steps 3 to 6
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
