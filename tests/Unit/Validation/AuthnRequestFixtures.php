<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Validation;

use function array_filter;
use function array_keys;
use function array_map;
use function array_merge;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\UnverifiedAuthnRequest;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use DateTimeImmutable;
use function implode;
use function sprintf;

/**
 * The fixtures the AuthnRequest tests share: the two parties of the files authn-request-*.xml of tests/Fixture/, a
 * service provider signing with the test key of its role and an identity provider at two single sign-on services; the
 * validator with a clock frozen at the IssueInstant of those files, or moved from it; the files, and the variants of
 * the unsigned request whose one change is a lexical value (section 9.7), built from the same attributes.
 */
final class AuthnRequestFixtures
{
    public const string NOW = '2026-10-01T12:00:00Z';

    public const string ID = '_4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b';

    public const string SERVICE_PROVIDER = 'https://sp.example.com/saml';

    public const string IDENTITY_PROVIDER = 'https://idp.example.com/saml';

    public const string SINGLE_SIGN_ON = 'https://idp.example.com/saml/sso';

    public const string ASSERTION_CONSUMER = 'https://sp.example.com/saml/acs';

    public const string POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

    public const string ISSUER = '<saml:Issuer>https://sp.example.com/saml</saml:Issuer>';

    /**
     * The service provider of the fixtures: its signing certificate the test key of $key, its assertion consumer
     * services at index 0 and at index 1, the second its default (SAML Metadata §2.2.3).
     *
     * @param 'idp'|'sp' $key
     */
    public static function serviceProvider(bool $authnRequestsSigned = false, string $key = 'sp'): ServiceProvider
    {
        return new ServiceProvider(
            self::SERVICE_PROVIDER,
            [MetadataFixtures::certificate($key)],
            [],
            new IndexedEndpoints([
                new IndexedEndpoint(Binding::HttpPost, self::ASSERTION_CONSUMER, 0),
                new IndexedEndpoint(Binding::HttpPost, self::ASSERTION_CONSUMER . '/second', 1, true),
            ]),
            authnRequestsSigned: $authnRequestsSigned,
        );
    }

    /**
     * Our identity provider: its single sign-on services on HTTP-Redirect and on HTTP-POST, at two locations.
     */
    public static function identityProvider(bool $wantAuthnRequestsSigned = false): IdentityProvider
    {
        return new IdentityProvider(
            self::IDENTITY_PROVIDER,
            [MetadataFixtures::certificate('idp')],
            [],
            [
                new Endpoint(Binding::HttpRedirect, self::SINGLE_SIGN_ON),
                new Endpoint(Binding::HttpPost, self::SINGLE_SIGN_ON . '/post'),
            ],
            wantAuthnRequestsSigned: $wantAuthnRequestsSigned,
        );
    }

    /**
     * The validator, its clock frozen at NOW moved by $seconds, the default bounds of section 7.
     */
    public static function validator(int $seconds = 0): AuthnRequestValidator
    {
        return new AuthnRequestValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable(self::NOW))->movedBy($seconds),
        );
    }

    /**
     * A file of tests/Fixture/, loaded with SamlLoader::create() (M-14) and read before verification (M-1).
     */
    public static function load(string $path): UnverifiedAuthnRequest
    {
        return UnverifiedAuthnRequest::of(MetadataFixtures::load($path));
    }

    /**
     * The unsigned request of behaviour/authn-request-unsigned.xml, each attribute of $changes replacing its own or
     * added, a null one removed, with $children as the children of the root.
     *
     * @param array<string, ?string> $changes
     */
    public static function request(array $changes = [], string $children = self::ISSUER): UnverifiedAuthnRequest
    {
        $attributes = array_filter(
            array_merge([
                'ID' => self::ID,
                'Version' => '2.0',
                'IssueInstant' => self::NOW,
                'Destination' => self::SINGLE_SIGN_ON,
                'AssertionConsumerServiceURL' => self::ASSERTION_CONSUMER,
                'ProtocolBinding' => self::POST,
            ], $changes),
            static fn (?string $value): bool => $value !== null,
        );

        return UnverifiedAuthnRequest::of(SamlLoader::create()->load(sprintf(
            '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" %s>%s</samlp:AuthnRequest>',
            implode(' ', array_map(
                static fn (string $name, string $value): string => sprintf('%s="%s"', $name, $value),
                array_keys($attributes),
                $attributes,
            )),
            $children,
        )));
    }
}
