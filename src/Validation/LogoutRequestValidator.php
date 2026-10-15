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
 * A samlp:LogoutRequest, received by either role, validated in the order of section 6.3 (section 5.6): its structure
 * and its bound before any key is touched, then the signature the Single Logout profile requires, its own or the
 * binding's (M-2, SAML Profiles §4.4.4.1), then its values from what that signature covered (M-1), and replay last
 * (M-11), so that nothing is remembered of a request a rule refused. now is read once from the clock (M-7).
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
     * The request as it arrived over HTTP-POST, or over HTTP-Redirect without a signature: its ds:Signature is
     * required and verified with the keys of $peer's metadata (M-2, M-3); without one it is SignatureRequired.
     *
     * @param IdentityProvider|ServiceProvider $self our role, the one that faces $peer's
     * @param string $receivedAt the URL of our SingleLogoutService at which the request arrived
     *
     * @throws MessageRefused one of its subclasses, naming the rule (M-16)
     * @throws Replayed when the message was accepted already, inside its window (M-11)
     * @throws RefusedXml what Core and Dsig refuse, as they refuse it
     * @throws InvalidArgumentException when $self is not the role that faces $peer's (section 5.6)
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
     * The request as it arrived over HTTP-Redirect with a signature over its query string, which saml2-bindings
     * verified with Verifier::verifyDetached() under $peer's keys before calling: the caller asserts it (section 6.8).
     * A ds:Signature child is refused, since the HTTP-Redirect encoding removes it (SAML Bindings §3.4.4.1).
     *
     * @param IdentityProvider|ServiceProvider $self our role, the one that faces $peer's
     * @param string $receivedAt the URL of our SingleLogoutService at which the request arrived
     *
     * @throws MessageRefused one of its subclasses, naming the rule (M-16)
     * @throws Replayed when the message was accepted already, inside its window (M-11)
     * @throws RefusedXml what Core refuses, as it refuses it
     * @throws InvalidArgumentException when $self is not the role that faces $peer's (section 5.6)
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
        // replay, last, with the verified values (M-11)
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
