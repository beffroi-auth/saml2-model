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
 * A samlp:LogoutResponse, received by either role, validated in the order of section 6.4 (section 5.6): its structure
 * before any key is touched, then the signature the Single Logout profile requires, its own or the binding's (M-2,
 * SAML Profiles §4.4.4.2), then its values from what that signature covered (M-1), its InResponseTo the request the
 * consumer names (M-10), and replay last (M-11), so that nothing is remembered of a response a rule refused. Its
 * status, whichever it is, is returned, never thrown. now is read once from the clock (M-7).
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
     * The response as it arrived over HTTP-POST, or over HTTP-Redirect without a signature: its ds:Signature is
     * required and verified with the keys of $peer's metadata (M-2, M-3); without one it is SignatureRequired.
     *
     * @param IdentityProvider|ServiceProvider $self our role, the one that faces $peer's
     * @param string $receivedAt the URL of our SingleLogoutService at which the response arrived
     * @param string $requestId the ID of the LogoutRequest the response answers (M-10)
     *
     * @throws MessageRefused one of its subclasses, naming the rule (M-16)
     * @throws Replayed when the message was accepted already, inside its window (M-11)
     * @throws RefusedXml what Core and Dsig refuse, as they refuse it
     * @throws InvalidArgumentException when $self is not the role that faces $peer's (section 5.6)
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
     * The response as it arrived over HTTP-Redirect with a signature over its query string, which saml2-bindings
     * verified with Verifier::verifyDetached() under $peer's keys before calling: the caller asserts it (section 6.8).
     * A ds:Signature child is refused, since the HTTP-Redirect encoding removes it (SAML Bindings §3.4.4.1).
     *
     * @param IdentityProvider|ServiceProvider $self our role, the one that faces $peer's
     * @param string $receivedAt the URL of our SingleLogoutService at which the response arrived
     * @param string $requestId the ID of the LogoutRequest the response answers (M-10)
     *
     * @throws MessageRefused one of its subclasses, naming the rule (M-16)
     * @throws Replayed when the message was accepted already, inside its window (M-11)
     * @throws RefusedXml what Core refuses, as it refuses it
     * @throws InvalidArgumentException when $self is not the role that faces $peer's (section 5.6)
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
        // replay, last, with the verified values (M-11); a response carries no NotOnOrAfter
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
