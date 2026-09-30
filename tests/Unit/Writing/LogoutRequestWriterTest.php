<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Writing;

use function array_fill;
use function array_map;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\LogoutRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutRequest;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Validation\LogoutFixtures;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Writing\LogoutRequestWriter;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use DateTimeImmutable;
use Dom\Element;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Sections 5.7 and 6.6, M-15: a samlp:LogoutRequest written, and read back by the validator of the peer role; the
 * logout request rows of section 9.1.
 */
final class LogoutRequestWriterTest extends TestCase
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * §9.1, M-15, SAML Profiles §4.4.4.1: a request signed for HTTP-POST, serialized with Core, loaded again with
     * SamlLoader::create(), is accepted by validate() of the peer as it was written.
     */
    #[Test]
    #[DataProvider('provideRequests')]
    public function itWritesASignedRequestTheValidatorOfThePeerAccepts(
        LogoutRequest $request,
        string $key,
        IdentityProvider|ServiceProvider $sender,
        IdentityProvider|ServiceProvider $receiver,
    ): void {
        // Given
        $document = LogoutFixtures::reload(new LogoutRequestWriter()->write(
            $request,
            new Signing(MetadataFixtures::signingKey($key === 'sp' ? 'sp' : 'idp')),
        ));

        // When
        $accepted = LogoutFixtures::requestValidator()->validate(
            UnverifiedLogoutRequest::of($document),
            $sender,
            $receiver,
            $request->destination,
        );

        // Then
        static::assertEquals([$request, Authentication::XmlSignature], [$accepted->request, $accepted->authentication]);
    }

    /**
     * §9.1, M-15, section 6.8: a request written unsigned for HTTP-Redirect, whose binding signs the query string, is
     * accepted by validateAuthenticatedByBinding() of the peer as it was written.
     */
    #[Test]
    #[DataProvider('provideRequests')]
    public function itWritesARequestForHttpRedirectTheValidatorOfThePeerAccepts(
        LogoutRequest $request,
        string $key,
        IdentityProvider|ServiceProvider $sender,
        IdentityProvider|ServiceProvider $receiver,
    ): void {
        // Given
        $document = LogoutFixtures::reload(new LogoutRequestWriter()->write($request, null));

        // When
        $accepted = LogoutFixtures::requestValidator()->validateAuthenticatedByBinding(
            UnverifiedLogoutRequest::of($document),
            $sender,
            $receiver,
            $request->destination,
        );

        // Then
        static::assertEquals([$request, Authentication::Binding], [$accepted->request, $accepted->authentication]);
    }

    /**
     * @return iterable<string, array{LogoutRequest, string, IdentityProvider|ServiceProvider, IdentityProvider|ServiceProvider}>
     */
    public static function provideRequests(): iterable
    {
        yield 'the identity provider to the service provider' => [
            LogoutFixtures::request(),
            'idp',
            LogoutFixtures::identityProvider(),
            LogoutFixtures::serviceProvider(),
        ];
        yield 'the service provider to the identity provider, without its optional parts' => [
            new LogoutRequest(
                LogoutFixtures::REQUEST_ID,
                new DateTimeImmutable(LogoutFixtures::NOW),
                new Issuer(LogoutFixtures::SP),
                LogoutFixtures::IDP_SLO_POST,
                null,
                new NameId('user@example.com'),
            ),
            'sp',
            LogoutFixtures::serviceProvider(),
            LogoutFixtures::identityProvider(),
        ];
        yield 'sixteen session indexes, an SPProvidedID' => [
            new LogoutRequest(
                LogoutFixtures::REQUEST_ID,
                new DateTimeImmutable(LogoutFixtures::NOW),
                new Issuer(LogoutFixtures::IDP),
                LogoutFixtures::SP_SLO,
                new DateTimeImmutable('2026-09-30T12:00:01Z'),
                new NameId('_7a2f4c1d9e', spProvidedId: 'local-7a2f'),
                array_fill(0, 16, '_session'),
                'urn:oasis:names:tc:SAML:2.0:logout:admin',
            ),
            'idp',
            LogoutFixtures::identityProvider(),
            LogoutFixtures::serviceProvider(),
        ];
    }

    /**
     * Section 6.6, M-15, SAML Core §3.2.1, §5.4.1: the Signature is enveloped after the Issuer, over the ID of the
     * request, with no InclusiveNamespaces; the prefixes are samlp and saml.
     */
    #[Test]
    public function itSignsAfterTheIssuer(): void
    {
        // When
        $root = new LogoutRequestWriter()
            ->write(
                LogoutFixtures::request(),
                new Signing(MetadataFixtures::signingKey('idp')),
            )
            ->root();

        // Then
        $reference = Children::one(
            Children::one(Children::one($root, new Name(self::DSIG, 'Signature')), new Name(self::DSIG, 'SignedInfo')),
            new Name(self::DSIG, 'Reference'),
        );
        static::assertSame(
            [
                ['saml:Issuer', 'ds:Signature', 'saml:NameID', 'samlp:SessionIndex'],
                '#' . LogoutFixtures::REQUEST_ID,
                'samlp:LogoutRequest',
            ],
            [
                array_map(static fn (Element $child): string => $child->nodeName, Children::all($root)),
                Attributes::required($reference, new Name(null, 'URI')),
                $root->nodeName,
            ],
        );
    }

    /**
     * Section 5.7, D-17: the certificate of the key travels in the KeyInfo when the signing asks for it.
     */
    #[Test]
    public function itCarriesTheCertificateWhenAsked(): void
    {
        // When
        $root = new LogoutRequestWriter()
            ->write(
                LogoutFixtures::request(),
                new Signing(
                    MetadataFixtures::signingKey('idp'),
                    certificatePem: MetadataFixtures::certificatePem('idp'),
                ),
            )
            ->root();

        // Then
        $keyInfo = Children::one(
            Children::one($root, new Name(self::DSIG, 'Signature')),
            new Name(self::DSIG, 'KeyInfo'),
        );
        static::assertSame(
            MetadataFixtures::certificate('idp'),
            Text::of(Children::one(
                Children::one($keyInfo, new Name(self::DSIG, 'X509Data')),
                new Name(self::DSIG, 'X509Certificate'),
            )),
        );
    }

    /**
     * Section 6.8, SAML Bindings §3.4.4.1: for HTTP-Redirect the request carries no ds:Signature.
     */
    #[Test]
    public function itWritesNoSignatureForHttpRedirect(): void
    {
        // When
        $root = new LogoutRequestWriter()
            ->write(LogoutFixtures::request(), null)
            ->root();

        // Then
        static::assertSame([], Children::named($root, new Name(self::DSIG, 'Signature')));
    }
}
