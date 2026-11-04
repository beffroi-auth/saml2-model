<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Validation;

use Beffroi\Saml2\Model\Exception\MessageRefused;
use Beffroi\Saml2\Model\Exception\Replayed;
use Beffroi\Saml2\Model\Internal\Logout\LogoutContext;
use Beffroi\Saml2\Model\Internal\Logout\LogoutRequestReader;
use Beffroi\Saml2\Model\Internal\Protocol\MessageAuthentication;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Internal\Logout\ReplayWindow;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Port\ReplayGuardInterface;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutRequest;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;

/**
 * Section 6.3, SAML Profiles §4.4.4.1
 */
final readonly class LogoutRequestValidator
{
    /**
     * @param Loader $loader SamlLoader::create(), the Verifier's too (M-14)
     */
    public function __construct(
        private Loader $loader,
        private ClockInterface $clock,
        private ReplayGuardInterface $replay,
        private TimeBounds $bounds = new TimeBounds(),
    ) {
    }

    /**
     * @param string $receivedAt the URL of our SingleLogoutService at which the request arrived
     *
     * @throws MessageRefused
     * @throws Replayed
     * @throws RefusedXml
     * @throws InvalidArgumentException when $self is not the role that faces $peer's
     */
    public function validate(
        UnverifiedLogoutRequest $request,
        IdentityProvider|ServiceProvider $peer,
        IdentityProvider|ServiceProvider $self,
        string $receivedAt,
    ): AcceptedLogoutRequest {
        $context = $this->context($peer, $self, $receivedAt);
        LogoutRequestReader::structure($request->document->root());

        return $this->accept(
            MessageAuthentication::signatureRequired($request->document, $peer->verificationKeys(), $this->loader),
            $context,
        );
    }

    /**
     * The caller asserts that saml2-bindings verified the signature over the query string under $peer's keys; a
     * ds:Signature child is refused (SAML Bindings §3.4.4.1).
     *
     * @param string $receivedAt the URL of our SingleLogoutService at which the request arrived
     *
     * @throws MessageRefused
     * @throws Replayed
     * @throws RefusedXml
     * @throws InvalidArgumentException when $self is not the role that faces $peer's
     */
    public function validateAuthenticatedByBinding(
        UnverifiedLogoutRequest $request,
        IdentityProvider|ServiceProvider $peer,
        IdentityProvider|ServiceProvider $self,
        string $receivedAt,
    ): AcceptedLogoutRequest {
        $context = $this->context($peer, $self, $receivedAt);
        LogoutRequestReader::structure($request->document->root());

        return $this->accept(MessageAuthentication::byBinding($request->document, $peer->verificationKeys()), $context);
    }

    /**
     * @throws InvalidArgumentException
     */
    private function context(
        IdentityProvider|ServiceProvider $peer,
        IdentityProvider|ServiceProvider $self,
        string $receivedAt,
    ): LogoutContext {
        return LogoutContext::forRequest(
            $this->clock->now(),
            $this->bounds,
            $peer,
            $self,
            $receivedAt,
        );
    }

    /**
     * @throws MessageRefused
     * @throws RefusedXml
     */
    private function accept(MessageAuthentication $authentication, LogoutContext $context): AcceptedLogoutRequest
    {
        $request = LogoutRequestReader::read($authentication->document->root(), $context);
        // Replay last, on the verified values: nothing is remembered of a request a rule refused (M-11).
        $remembered = $this->replay->remember(
            $request->issuer->entityId,
            $request->id,
            ReplayWindow::until($context->window, $request->issueInstant, $request->notOnOrAfter),
        );
        if (! $remembered) {
            throw new Replayed('The logout message was already accepted from its issuer (M-11).');
        }

        return new AcceptedLogoutRequest($request, $authentication->authentication);
    }
}
