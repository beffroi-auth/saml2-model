<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Writing;

use function array_map;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\LogoutResponse;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutResponse;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Validation\LogoutFixtures;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Writing\LogoutResponseWriter;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use DateTimeImmutable;
use Dom\Element;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Sections 5.7 and 6.6, M-15: a samlp:LogoutResponse written, and read back by the validator of the peer role; the
 * logout response rows of section 9.1.
 */
final class LogoutResponseWriterTest extends TestCase
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * §9.1, M-15, SAML Profiles §4.4.4.2: a response signed for HTTP-POST, serialized with Core, loaded again with
     * SamlLoader::create(), is accepted by validate() of the peer as it was written, whatever its status.
     */
    #[Test]
    #[DataProvider('provideResponses')]
    public function itWritesASignedResponseTheValidatorOfThePeerAccepts(
        LogoutResponse $response,
        string $key,
        IdentityProvider|ServiceProvider $sender,
        IdentityProvider|ServiceProvider $receiver,
    ): void {
        // Given
        $document = LogoutFixtures::reload(new LogoutResponseWriter()->write(
            $response,
            new Signing(MetadataFixtures::signingKey($key === 'sp' ? 'sp' : 'idp')),
        ));

        // When
        $accepted = LogoutFixtures::responseValidator()->validate(
            UnverifiedLogoutResponse::of($document),
            $sender,
            $receiver,
            $response->destination,
            LogoutFixtures::REQUEST_ID,
        );

        // Then
        static::assertEquals([$response, Authentication::XmlSignature], [
            $accepted->response,
            $accepted->authentication,
        ]);
    }

    /**
     * §9.1, M-15, section 6.8: a response written unsigned for HTTP-Redirect, whose binding signs the query string, is
     * accepted by validateAuthenticatedByBinding() of the peer as it was written.
     */
    #[Test]
    #[DataProvider('provideResponses')]
    public function itWritesAResponseForHttpRedirectTheValidatorOfThePeerAccepts(
        LogoutResponse $response,
        string $key,
        IdentityProvider|ServiceProvider $sender,
        IdentityProvider|ServiceProvider $receiver,
    ): void {
        // Given
        $document = LogoutFixtures::reload(new LogoutResponseWriter()->write($response, null));

        // When
        $accepted = LogoutFixtures::responseValidator()->validateAuthenticatedByBinding(
            UnverifiedLogoutResponse::of($document),
            $sender,
            $receiver,
            $response->destination,
            LogoutFixtures::REQUEST_ID,
        );

        // Then
        static::assertEquals([$response, Authentication::Binding], [$accepted->response, $accepted->authentication]);
    }

    /**
     * @return iterable<string, array{LogoutResponse, string, IdentityProvider|ServiceProvider, IdentityProvider|ServiceProvider}>
     */
    public static function provideResponses(): iterable
    {
        yield 'the service provider to the identity provider, Success' => [
            LogoutFixtures::response(),
            'sp',
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::identityProvider(),
        ];
        yield 'a partial logout' => [
            LogoutFixtures::response(LogoutFixtures::partialLogout()),
            'sp',
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::identityProvider(),
        ];
        yield 'the identity provider to the service provider, Responder and RequestDenied' => [
            new LogoutResponse(
                LogoutFixtures::RESPONSE_ID,
                new DateTimeImmutable(LogoutFixtures::NOW),
                new Issuer(LogoutFixtures::IDP),
                LogoutFixtures::SP_SLO,
                LogoutFixtures::REQUEST_ID,
                new Status(StatusCode::Responder, SecondLevelStatusCode::RequestDenied),
            ),
            'idp',
            LogoutFixtures::identityProvider(),
            LogoutFixtures::serviceProvider(),
        ];
    }

    /**
     * Section 6.6, M-15, SAML Core §3.2.1, §5.4.1: the Signature is enveloped after the Issuer, over the ID of the
     * response, before the Status; the prefixes are samlp and saml.
     */
    #[Test]
    public function itSignsAfterTheIssuer(): void
    {
        // When
        $root = new LogoutResponseWriter()
            ->write(
                LogoutFixtures::response(),
                new Signing(MetadataFixtures::signingKey('sp')),
            )
            ->root();

        // Then
        $reference = Children::one(
            Children::one(Children::one($root, new Name(self::DSIG, 'Signature')), new Name(self::DSIG, 'SignedInfo')),
            new Name(self::DSIG, 'Reference'),
        );
        static::assertSame(
            [
                ['saml:Issuer', 'ds:Signature', 'samlp:Status'],
                '#' . LogoutFixtures::RESPONSE_ID,
                'samlp:LogoutResponse',
            ],
            [
                array_map(static fn (Element $child): string => $child->nodeName, Children::all($root)),
                Attributes::required($reference, new Name(null, 'URI')),
                $root->nodeName,
            ],
        );
    }

    /**
     * Section 6.8, SAML Bindings §3.4.4.1: for HTTP-Redirect the response carries no ds:Signature.
     */
    #[Test]
    public function itWritesNoSignatureForHttpRedirect(): void
    {
        // When
        $root = new LogoutResponseWriter()
            ->write(LogoutFixtures::response(), null)
            ->root();

        // Then
        static::assertSame([], Children::named($root, new Name(self::DSIG, 'Signature')));
    }
}
