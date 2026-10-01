<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Validation;

use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\LogoutRequest;
use Beffroi\Saml2\Model\Protocol\LogoutResponse;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Validation\LogoutRequestValidator;
use Beffroi\Saml2\Model\Validation\LogoutResponseValidator;
use Beffroi\Saml2\Model\Validation\TimeBounds;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Serializer;
use DateTimeImmutable;

/**
 * The parties, the clock and the messages the logout tests share (sections 6.3, 6.4 and 9.1): an identity provider
 * and a service provider carrying the test keys of tests/Fixture/keys/, the identity provider's request to the service
 * provider and the service provider's response to it, the clock frozen at their IssueInstant.
 */
final class LogoutFixtures
{
    public const string IDP = 'https://idp.example.com/saml';

    public const string SP = 'https://sp.example.com/saml';

    /** The single logout service of the service provider, on both bindings, where the request arrives. */
    public const string SP_SLO = 'https://sp.example.com/saml/slo';

    /** The single logout service of the identity provider on HTTP-Redirect, without ResponseLocation. */
    public const string IDP_SLO = 'https://idp.example.com/saml/slo';

    /** The Location of the identity provider's single logout service on HTTP-POST, where a request arrives. */
    public const string IDP_SLO_POST = 'https://idp.example.com/saml/slo/post';

    /** Its ResponseLocation, where a response arrives (SAML Metadata §2.2.2). */
    public const string IDP_SLO_RESPONSE = 'https://idp.example.com/saml/slo/response';

    public const string REQUEST_ID = '_5d1a0e7c9b3f4a2e8d6c1b0a9f8e7d6c5b4a3f2e';

    public const string RESPONSE_ID = '_6e2b1f8d0c4a5b3f9e7d2c1b0a9f8e7d6c5b4a3f';

    public const string NOW = '2026-09-30T12:00:00Z';

    public static function identityProvider(string $certificate = 'idp'): IdentityProvider
    {
        return new IdentityProvider(
            self::IDP,
            $certificate === '' ? [] : [MetadataFixtures::certificate($certificate === 'sp' ? 'sp' : 'idp')],
            [],
            [new Endpoint(Binding::HttpRedirect, 'https://idp.example.com/saml/sso')],
            [
                new Endpoint(Binding::HttpRedirect, self::IDP_SLO),
                new Endpoint(Binding::HttpPost, self::IDP_SLO_POST, self::IDP_SLO_RESPONSE),
            ],
        );
    }

    public static function serviceProvider(string $certificate = 'sp'): ServiceProvider
    {
        return new ServiceProvider(
            self::SP,
            $certificate === '' ? [] : [MetadataFixtures::certificate($certificate === 'idp' ? 'idp' : 'sp')],
            [],
            new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, 'https://sp.example.com/saml/acs', 0)]),
            [new Endpoint(Binding::HttpRedirect, self::SP_SLO), new Endpoint(Binding::HttpPost, self::SP_SLO)],
        );
    }

    /**
     * The identity provider's LogoutRequest to the service provider, which expires five minutes after its issue and
     * says the user asked for it (SAML Core §3.7.3).
     *
     * @param list<string> $sessionIndexes
     */
    public static function request(
        ?DateTimeImmutable $notOnOrAfter = new DateTimeImmutable('2026-09-30T12:05:00Z'),
        array $sessionIndexes = ['_session-1'],
        ?string $reason = 'urn:oasis:names:tc:SAML:2.0:logout:user',
    ): LogoutRequest {
        return new LogoutRequest(
            self::REQUEST_ID,
            new DateTimeImmutable(self::NOW),
            new Issuer(self::IDP),
            self::SP_SLO,
            $notOnOrAfter,
            new NameId('_7a2f4c1d9e', NameIdFormat::Persistent, self::IDP, self::SP),
            $sessionIndexes,
            $reason,
        );
    }

    /**
     * The service provider's LogoutResponse to the identity provider's request, at the identity provider's
     * ResponseLocation.
     */
    public static function response(
        Status $status = new Status(StatusCode::Success),
        string $destination = self::IDP_SLO_RESPONSE,
    ): LogoutResponse {
        return new LogoutResponse(
            self::RESPONSE_ID,
            new DateTimeImmutable(self::NOW),
            new Issuer(self::SP),
            $destination,
            self::REQUEST_ID,
            $status,
        );
    }

    public static function partialLogout(): Status
    {
        return new Status(StatusCode::Success, SecondLevelStatusCode::PartialLogout);
    }

    public static function clock(int $seconds = 0): FrozenClock
    {
        return new FrozenClock(new DateTimeImmutable(self::NOW))->movedBy($seconds);
    }

    public static function requestValidator(int $seconds = 0): LogoutRequestValidator
    {
        return new LogoutRequestValidator(SamlLoader::create(), self::clock($seconds), new TimeBounds());
    }

    public static function responseValidator(int $seconds = 0): LogoutResponseValidator
    {
        return new LogoutResponseValidator(SamlLoader::create(), self::clock($seconds), new TimeBounds());
    }

    /**
     * A written document as its peer receives it: serialized with Core, loaded again with SamlLoader::create()
     * (section 9.1).
     */
    public static function reload(Document $document): Document
    {
        return SamlLoader::create()->load(new Serializer()->serialize($document));
    }
}
