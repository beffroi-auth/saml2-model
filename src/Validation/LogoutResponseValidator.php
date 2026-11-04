<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Validation;

use Beffroi\Saml2\Model\Exception\MessageRefused;
use Beffroi\Saml2\Model\Exception\Replayed;
use Beffroi\Saml2\Model\Internal\Logout\LogoutContext;
use Beffroi\Saml2\Model\Internal\Logout\LogoutResponseReader;
use Beffroi\Saml2\Model\Internal\Protocol\MessageAuthentication;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Internal\Logout\ReplayWindow;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Port\ReplayGuardInterface;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutResponse;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;

/**
 * Section 6.4, SAML Profiles §4.4.4.2
 */
final readonly class LogoutResponseValidator
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
     * @param string $receivedAt the URL of our SingleLogoutService at which the response arrived
     *
     * @throws MessageRefused
     * @throws Replayed
     * @throws RefusedXml
     * @throws InvalidArgumentException when $self is not the role that faces $peer's
     */
    public function validate(
        UnverifiedLogoutResponse $response,
        IdentityProvider|ServiceProvider $peer,
        IdentityProvider|ServiceProvider $self,
        string $receivedAt,
        string $requestId,
    ): AcceptedLogoutResponse {
        $context = $this->context($peer, $self, $receivedAt);
        LogoutResponseReader::structure($response->document->root());

        return $this->accept(
            MessageAuthentication::signatureRequired($response->document, $peer->verificationKeys(), $this->loader),
            $context,
            $requestId,
        );
    }

    /**
     * The caller asserts that saml2-bindings verified the signature over the query string under $peer's keys; a
     * ds:Signature child is refused (SAML Bindings §3.4.4.1).
     *
     * @param string $receivedAt the URL of our SingleLogoutService at which the response arrived
     *
     * @throws MessageRefused
     * @throws Replayed
     * @throws RefusedXml
     * @throws InvalidArgumentException when $self is not the role that faces $peer's
     */
    public function validateAuthenticatedByBinding(
        UnverifiedLogoutResponse $response,
        IdentityProvider|ServiceProvider $peer,
        IdentityProvider|ServiceProvider $self,
        string $receivedAt,
        string $requestId,
    ): AcceptedLogoutResponse {
        $context = $this->context($peer, $self, $receivedAt);
        LogoutResponseReader::structure($response->document->root());

        return $this->accept(
            MessageAuthentication::byBinding($response->document, $peer->verificationKeys()),
            $context,
            $requestId,
        );
    }

    /**
     * @throws InvalidArgumentException
     */
    private function context(
        IdentityProvider|ServiceProvider $peer,
        IdentityProvider|ServiceProvider $self,
        string $receivedAt,
    ): LogoutContext {
        return LogoutContext::forResponse(
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
    private function accept(
        MessageAuthentication $authentication,
        LogoutContext $context,
        string $requestId,
    ): AcceptedLogoutResponse {
        $response = LogoutResponseReader::read($authentication->document->root(), $context, $requestId);
        // Replay last: nothing is remembered of a response a rule refused; a response carries no NotOnOrAfter.
        $remembered = $this->replay->remember(
            $response->issuer->entityId,
            $response->id,
            ReplayWindow::until($context->window, $response->issueInstant, null),
        );
        if (! $remembered) {
            throw new Replayed('The logout message was already accepted from its issuer (M-11).');
        }

        return new AcceptedLogoutResponse($response, $authentication->authentication);
    }
}
