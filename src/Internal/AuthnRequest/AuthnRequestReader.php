<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\AuthnRequest;

use function array_any;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Exception\DestinationMismatch;
use Beffroi\Saml2\Model\Exception\IssuerMismatch;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\MessageRefused;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Assertion\IssuerReader;
use Beffroi\Saml2\Model\Internal\Particle;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Value\Boolean;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Saml2\Model\Value\Uri;
use Beffroi\Saml2\Model\Value\Version;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use DateTimeImmutable;
use Dom\Element;

/**
 * Section 6.2
 *
 * @internal
 */
final readonly class AuthnRequestReader
{
    /**
     * Section 6.2 step 1
     *
     * @throws Unsupported
     * @throws MalformedMessage
     */
    public static function structure(Element $request): void
    {
        Schema::unsupported(
            $request,
            [Schema::saml('Subject'), Schema::saml('Conditions'), Schema::samlp('Scoping')],
            'The samlp:AuthnRequest holds a saml:Subject, a saml:Conditions or a samlp:Scoping, which the package does not support (section 8).',
        );
        Schema::children($request, 'samlp:AuthnRequest', [
            Particle::of(Schema::saml('Issuer'), 1, 1),
            Particle::of(Schema::ds('Signature'), 0, 1),
            Particle::of(Schema::samlp('Extensions'), 0, 1),
            Particle::of(Schema::samlp('NameIDPolicy'), 0, 1),
            Particle::of(Schema::samlp('RequestedAuthnContext'), 0, 1),
        ]);
    }

    /**
     * Section 6.2 steps 3 to 5, M-1
     *
     * @return array{AuthnRequest, IndexedEndpoint}
     *
     * @throws MessageRefused
     * @throws MixedContent
     */
    public static function read(Element $request, AuthnRequestContext $context): array
    {
        [$id, $issueInstant, $destination, $issuer] = self::header($request, $context);
        [$endpoint, $url, $index, $binding] = AssertionConsumerService::read(
            $request,
            $context->serviceProvider->assertionConsumerServices,
        );
        $forceAuthn = Attributes::optional($request, new Name(null, 'ForceAuthn'));
        $isPassive = Attributes::optional($request, new Name(null, 'IsPassive'));
        $policy = Children::optional($request, Schema::samlp('NameIDPolicy'));
        $nameIdPolicy = $policy instanceof Element ? NameIdPolicyReader::read($policy) : null;
        // Honouring an affiliation the package does not read would hand the requester the identifier the user has
        // at another entity (SAML Core §3.4.1.1).
        if ($nameIdPolicy?->spNameQualifier !== null && $nameIdPolicy->spNameQualifier !== $context->serviceProvider->entityId) {
            throw new Unsupported('The SPNameQualifier of the samlp:NameIDPolicy names another entity than the service provider, an affiliation the package does not read (section 8).');
        }
        $requested = Children::optional($request, Schema::samlp('RequestedAuthnContext'));

        return [
            new AuthnRequest(
                $id,
                $issueInstant,
                $issuer,
                $destination,
                $url,
                $index,
                $binding,
                $nameIdPolicy,
                $forceAuthn !== null && Boolean::read($forceAuthn),
                $isPassive !== null && Boolean::read($isPassive),
                $requested instanceof Element ? RequestedAuthnContextReader::read($requested) : null,
            ),
            $endpoint,
        ];
    }

    /**
     * Section 6.2 step 3
     *
     * @return array{string, DateTimeImmutable, ?string, Issuer}
     *
     * @throws MalformedMessage
     * @throws OutsideValidityWindow
     * @throws DestinationMismatch
     * @throws IssuerMismatch
     * @throws MixedContent
     */
    private static function header(Element $request, AuthnRequestContext $context): array
    {
        Version::read(Schema::attribute($request, 'samlp:AuthnRequest', 'Version'));
        // The loader's ID attributes already refused anything but an NCName of at most 128 bytes (M-14, I-8).
        $id = Schema::attribute($request, 'samlp:AuthnRequest', 'ID');
        $issueInstant = Time::read(Schema::attribute($request, 'samlp:AuthnRequest', 'IssueInstant'));
        if ($issueInstant > $context->window->latest()) {
            throw new OutsideValidityWindow('The IssueInstant of the request is later than now plus the clock skew (M-7).');
        }
        if ($issueInstant < $context->window->oldest()) {
            throw new OutsideValidityWindow('The IssueInstant of the request is older than maxMessageAge (M-7).');
        }
        $destination = Attributes::optional($request, new Name(null, 'Destination'));
        $destination = $destination === null ? null : Uri::read($destination);
        if ($destination === null && $context->authentication !== Authentication::None) {
            throw new DestinationMismatch('The request is signed, by XML or by the binding, and carries no Destination (M-8).');
        }
        if ($destination !== null && $destination !== $context->receivedAt) {
            throw new DestinationMismatch('The Destination of the request is not the URL at which it arrived (M-8).');
        }
        if (! array_any(
            $context->identityProvider->singleSignOnServices,
            static fn (Endpoint $service): bool => $service->location === $context->receivedAt,
        )) {
            throw new DestinationMismatch('The URL at which the request arrived is not a single sign-on service of the identity provider (M-8).');
        }

        return [
            $id,
            $issueInstant,
            $destination,
            IssuerReader::read(
                Children::one($request, Schema::saml('Issuer')),
                $context->serviceProvider->entityId,
            ),
        ];
    }
}
