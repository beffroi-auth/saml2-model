<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Writing;

use function array_map;
use Beffroi\Saml2\Model\Assertion\Assertion;
use Beffroi\Saml2\Model\Assertion\Attribute;
use Beffroi\Saml2\Model\Assertion\AttributeNameFormat;
use Beffroi\Saml2\Model\Assertion\AuthnStatement;
use Beffroi\Saml2\Model\Assertion\Conditions;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Assertion\SubjectConfirmation;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Protocol\Response;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Core\Text;
use DateTimeImmutable;
use Dom\Element;

/**
 * The responses the identity provider https://idp.example.com/saml writes to the service provider
 * https://sp.example.com/saml, at its assertion consumer service https://sp.example.com/saml/acs, answering the request
 * _4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b or none, issued at 2026-10-01T12:00:00Z, where the clock of the validator
 * is frozen (section 9.1); and what reads them back: the identity provider's metadata carrying its test key, the
 * validator of the service provider.
 */
final class ResponseWriterFixtures
{
    public const string NOW = '2026-10-01T12:00:00Z';

    public const string REQUEST = '_4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b';

    public const string IDENTITY_PROVIDER = 'https://idp.example.com/saml';

    public const string SERVICE_PROVIDER = 'https://sp.example.com/saml';

    public const string ASSERTION_CONSUMER = 'https://sp.example.com/saml/acs';

    public const string CONTEXT_CLASS = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';

    /**
     * A response whose status is Success, carrying $assertion, to the request $inResponseTo or unsolicited.
     */
    public static function response(
        ?Assertion $assertion = null,
        ?string $inResponseTo = self::REQUEST,
        ?string $destination = self::ASSERTION_CONSUMER,
        string $issuer = self::IDENTITY_PROVIDER,
        ?string $id = null,
    ): Response {
        return new Response(
            $id ?? SamlId::generate(),
            new DateTimeImmutable(self::NOW),
            new Issuer($issuer),
            $destination,
            $inResponseTo,
            new Status(StatusCode::Success),
            $assertion ?? self::assertion(inResponseTo: $inResponseTo),
        );
    }

    /**
     * A failure Responder / AuthnFailed to the request, without assertion (M-13).
     */
    public static function failure(
        ?SecondLevelStatusCode $secondLevel = SecondLevelStatusCode::AuthnFailed,
        ?string $destination = self::ASSERTION_CONSUMER,
    ): Response {
        return new Response(
            SamlId::generate(),
            new DateTimeImmutable(self::NOW),
            new Issuer(self::IDENTITY_PROVIDER),
            $destination,
            self::REQUEST,
            new Status(StatusCode::Responder, $secondLevel),
            null,
        );
    }

    /**
     * The assertion with the parts the profile requires only: an unspecified NameID, a confirmation without Address,
     * Conditions without window holding one AudienceRestriction of one Audience, an authentication statement without
     * SessionNotOnOrAfter, no attribute.
     */
    public static function assertion(
        ?string $inResponseTo = self::REQUEST,
        ?string $sessionIndex = '_session',
        string $issuer = self::IDENTITY_PROVIDER,
        string $recipient = self::ASSERTION_CONSUMER,
        ?string $id = null,
        string $issueInstant = self::NOW,
        ?Conditions $conditions = null,
    ): Assertion {
        return new Assertion(
            $id ?? SamlId::generate(),
            new DateTimeImmutable($issueInstant),
            new Issuer($issuer),
            new NameId('alice'),
            new SubjectConfirmation($recipient, new DateTimeImmutable('2026-10-01T12:05:00Z'), $inResponseTo, null),
            $conditions ?? new Conditions(null, null, [[self::SERVICE_PROVIDER]], false),
            new AuthnStatement(new DateTimeImmutable('2026-10-01T11:59:30Z'), $sessionIndex, null, self::CONTEXT_CLASS),
            [],
        );
    }

    /**
     * The assertion with every optional part: a persistent NameID with its three qualifiers, a confirmation with its
     * Address, Conditions with their window, two AudienceRestriction and OneTimeUse, a SessionNotOnOrAfter, and three
     * attributes, one of each NameFormat, with a FriendlyName or without, with two values, one or none.
     */
    public static function everything(?string $inResponseTo = self::REQUEST): Assertion
    {
        return new Assertion(
            SamlId::generate(),
            new DateTimeImmutable(self::NOW),
            new Issuer(self::IDENTITY_PROVIDER),
            new NameId(
                'b2c1a8f0-4e67-4a0b-9d1c-3f5e7a9b1c2d',
                NameIdFormat::Persistent,
                self::IDENTITY_PROVIDER,
                self::SERVICE_PROVIDER,
                'alice-at-sp',
            ),
            new SubjectConfirmation(
                self::ASSERTION_CONSUMER,
                new DateTimeImmutable('2026-10-01T12:05:00Z'),
                $inResponseTo,
                '192.0.2.10',
            ),
            new Conditions(
                new DateTimeImmutable('2026-10-01T11:59:00Z'),
                new DateTimeImmutable('2026-10-01T12:10:00Z'),
                [[self::SERVICE_PROVIDER, 'https://other.example.com/saml'], [self::SERVICE_PROVIDER]],
                true,
            ),
            new AuthnStatement(
                new DateTimeImmutable('2026-10-01T11:59:30Z'),
                '_session',
                new DateTimeImmutable('2026-10-01T20:00:00Z'),
                self::CONTEXT_CLASS,
            ),
            [
                new Attribute(
                    'urn:oid:0.9.2342.19200300.100.1.3',
                    AttributeNameFormat::Uri,
                    'mail',
                    ['alice@example.com', 'alice@example.org'],
                ),
                new Attribute('groups', AttributeNameFormat::Unspecified, null, ['admins']),
                new Attribute('locked', AttributeNameFormat::Basic, null, []),
            ],
        );
    }

    /**
     * The metadata of the identity provider, its signing key the identity provider's test key (M-3).
     */
    public static function identityProvider(): IdentityProvider
    {
        return new IdentityProvider(
            self::IDENTITY_PROVIDER,
            [MetadataFixtures::certificate('idp')],
            [],
            [new Endpoint(Binding::HttpRedirect, 'https://idp.example.com/saml/sso')],
        );
    }

    /**
     * The validator of the service provider, its clock frozen at the IssueInstant of the responses.
     */
    public static function validator(): ResponseValidator
    {
        return new ResponseValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable(self::NOW)),
            new InMemoryReplayGuard(),
        );
    }

    /**
     * What the service provider expects: an answer to the request $requestId, or an unsolicited response.
     */
    public static function expected(?string $requestId = self::REQUEST): ExpectedResponse
    {
        if ($requestId === null) {
            return ExpectedResponse::unsolicited(self::ASSERTION_CONSUMER, self::SERVICE_PROVIDER);
        }

        return ExpectedResponse::toRequest($requestId, self::ASSERTION_CONSUMER, self::SERVICE_PROVIDER);
    }

    /**
     * The document serialized with Core and loaded again with SamlLoader::create(), as the service provider receives
     * it (section 9.1).
     */
    public static function reload(Document $document): UnverifiedResponse
    {
        return UnverifiedResponse::of(SamlLoader::create()->load(new Serializer()->serialize($document)));
    }

    /**
     * The qualified names of the element children of $element, in document order.
     *
     * @param iterable<Element> $children
     *
     * @return list<string>
     */
    public static function names(iterable $children): array
    {
        $names = [];
        foreach ($children as $child) {
            $names[] = $child->nodeName;
        }

        return $names;
    }

    /**
     * The attributes in no namespace, in document order, the namespace declarations left aside.
     *
     * @return array<string, string>
     */
    public static function attributes(Element $element): array
    {
        $attributes = [];
        foreach ($element->attributes as $attribute) {
            if ($attribute->namespaceURI !== null) {
                continue;
            }
            $attributes[$attribute->localName] = $attribute->value;
        }

        return $attributes;
    }

    /**
     * The namespace declarations an element carries as attributes, prefix to namespace.
     *
     * @return array<string, string>
     */
    public static function declarations(Element $element): array
    {
        $declarations = [];
        foreach ($element->attributes as $attribute) {
            if ($attribute->namespaceURI !== 'http://www.w3.org/2000/xmlns/') {
                continue;
            }

            $declarations[$attribute->localName] = $attribute->value;
        }

        return $declarations;
    }

    /**
     * The texts of $elements, in document order.
     *
     * @param list<Element> $elements
     *
     * @return list<string>
     */
    public static function texts(array $elements): array
    {
        return array_map(Text::of(...), $elements);
    }
}
