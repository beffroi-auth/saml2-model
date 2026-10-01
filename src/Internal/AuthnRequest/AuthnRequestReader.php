<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\AuthnRequest;

use function array_any;
use function array_keys;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Exception\DestinationMismatch;
use Beffroi\Saml2\Model\Exception\IssuerMismatch;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\MessageRefused;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Assertion\IssuerReader;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Saml;
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
use function sprintf;

/**
 * The strict reader of a samlp:AuthnRequest, section 6.2 in order: structure() is step 1, over the request as it
 * arrived, before any signature is touched; read() is steps 3 to 5, over the document of the authentication (M-1),
 * the header, the assertion consumer service (M-9), then what the request asks, returned and never enforced. The
 * validator runs step 2, the signature, between the two, and step 6, the result, after them.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class AuthnRequestReader
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * Section 6.2 step 1: the children in the order and with the cardinality of the schema (SAML Core §3.2.1,
     * §3.4.1), the saml:Issuer required (Profiles §4.1.4.1), found as direct children only (M-4, I-11); saml:Subject,
     * saml:Conditions and samlp:Scoping refused by name wherever they are (section 8).
     *
     * @throws Unsupported when it holds a saml:Subject, a saml:Conditions or a samlp:Scoping (section 8)
     * @throws MalformedMessage when a child is not allowed there, is out of order or repeated (M-5), or the saml:Issuer
     *                          is missing (M-4)
     */
    public static function structure(Element $request): void
    {
        $unsupported = [
            new Name(Saml::ASSERTION, 'Subject'),
            new Name(Saml::ASSERTION, 'Conditions'),
            new Name(Saml::PROTOCOL, 'Scoping'),
        ];
        foreach (Children::all($request) as $child) {
            if (array_any($unsupported, static fn (Name $name): bool => $name->matches($child))) {
                throw new Unsupported('The samlp:AuthnRequest holds a saml:Subject, a saml:Conditions or a samlp:Scoping, which the package does not support (section 8).');
            }
        }
        $sequence = [
            'saml:Issuer' => new Name(Saml::ASSERTION, 'Issuer'),
            'ds:Signature' => new Name(self::DSIG, 'Signature'),
            'samlp:Extensions' => new Name(Saml::PROTOCOL, 'Extensions'),
            'samlp:NameIDPolicy' => new Name(Saml::PROTOCOL, 'NameIDPolicy'),
            'samlp:RequestedAuthnContext' => new Name(Saml::PROTOCOL, 'RequestedAuthnContext'),
        ];
        $labels = array_keys($sequence);
        $previous = -1;
        foreach (Children::all($request) as $child) {
            $place = self::place($sequence, $child);
            if ($place === null || $place < $previous) {
                throw new MalformedMessage('The samlp:AuthnRequest holds a child the schema does not allow there, or out of its order (M-5).');
            }
            if ($place === $previous) {
                throw new MalformedMessage(sprintf(
                    'The samlp:AuthnRequest holds more than one %s (M-4).',
                    $labels[$place],
                ));
            }
            $previous = $place;
        }
        if (Children::named($request, $sequence['saml:Issuer']) === []) {
            throw new MalformedMessage('The samlp:AuthnRequest holds no saml:Issuer (M-4).');
        }
    }

    /**
     * Section 6.2 steps 3 to 5, over the root of the document the authentication handed over (M-1), whose structure
     * step 1 checked on the request as it arrived.
     *
     * @return array{AuthnRequest, IndexedEndpoint} the request, and the assertion consumer service it resolves to
     *
     * @throws MessageRefused one of its subclasses, naming the rule (M-16)
     * @throws MixedContent when the Issuer or a class reference holds an element
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
        $policy = Children::optional($request, new Name(Saml::PROTOCOL, 'NameIDPolicy'));
        $requested = Children::optional($request, new Name(Saml::PROTOCOL, 'RequestedAuthnContext'));

        return [
            new AuthnRequest(
                $id,
                $issueInstant,
                $issuer,
                $destination,
                $url,
                $index,
                $binding,
                $policy instanceof Element ? NameIdPolicyReader::read($policy) : null,
                $forceAuthn !== null && Boolean::read($forceAuthn),
                $isPassive !== null && Boolean::read($isPassive),
                $requested instanceof Element ? RequestedAuthnContextReader::read($requested) : null,
            ),
            $endpoint,
        ];
    }

    /**
     * Section 6.2 step 3: Version 2.0, the ID present, the IssueInstant not later than now plus the skew and
     * not older than maxMessageAge (M-7); the Destination required when the request carries a signature, its own or
     * the binding's, equal to the URL at which it arrived whenever present, that URL one of our single sign-on
     * services (M-8); the Issuer the service provider's entity ID, read by the one reader of an Issuer, its Format
     * omitted or entity and no qualifier (M-8).
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
        Version::read(self::attribute($request, 'Version'));
        // an NCName of at most 128 bytes: the loader's ID attributes refused any other (M-14, I-8), AuthnRequest checks
        // it again for whoever builds one
        $id = self::attribute($request, 'ID');
        $issueInstant = Time::read(self::attribute($request, 'IssueInstant'));
        if ($issueInstant > $context->latest) {
            throw new OutsideValidityWindow('The IssueInstant of the request is later than now plus the clock skew (M-7).');
        }
        if ($issueInstant < $context->oldest) {
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
                Children::one($request, new Name(Saml::ASSERTION, 'Issuer')),
                $context->serviceProvider->entityId,
            ),
        ];
    }

    /**
     * @throws MalformedMessage when the attribute, which the schema requires, is absent (M-5)
     */
    private static function attribute(Element $request, string $attribute): string
    {
        return (
            Attributes::optional($request, new Name(null, $attribute)) ?? throw new MalformedMessage(sprintf(
                'The samlp:AuthnRequest has no %s (M-5).',
                $attribute,
            ))
        );
    }

    /**
     * The place of $child in the sequence, or null when no place accepts it.
     *
     * @param array<string, Name> $sequence
     */
    private static function place(array $sequence, Element $child): ?int
    {
        $place = 0;
        foreach ($sequence as $name) {
            if ($name->matches($child)) {
                return $place;
            }
            $place++;
        }

        return null;
    }
}
