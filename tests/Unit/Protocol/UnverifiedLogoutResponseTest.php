<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Protocol;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutResponse;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Validation\LogoutFixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_replace;

/**
 * Section 5.4, M-1: a received samlp:LogoutResponse before any verification, its root checked, its Issuer and its
 * InResponseTo read to choose the peer and the request, nothing else.
 */
final class UnverifiedLogoutResponseTest extends TestCase
{
    private const string RESPONSE = 'behaviour/logout-response-written-for-http-redirect.xml';

    /**
     * Section 5.4: the Issuer, the InResponseTo, and the document held for the validator.
     */
    #[Test]
    public function itReadsTheIssuerAndTheInResponseTo(): void
    {
        // Given
        $document = MetadataFixtures::load(self::RESPONSE);

        // When
        $response = UnverifiedLogoutResponse::of($document);

        // Then
        static::assertSame([LogoutFixtures::SP, LogoutFixtures::REQUEST_ID, $document], [
            $response->issuer,
            $response->inResponseTo,
            $response->document,
        ]);
    }

    /**
     * Section 5.4, SAML Core §3.2.2: the Issuer and the InResponseTo the schema leaves optional are read as null; the
     * validator refuses their absence (SAML Profiles §4.4.4.2, M-10).
     */
    #[Test]
    public function itReadsNoIssuerAndNoInResponseToAsNull(): void
    {
        // Given
        $document = SamlLoader::create()->load(str_replace(
            ' InResponseTo="' . LogoutFixtures::REQUEST_ID . '"',
            '',
            MetadataFixtures::bytes('hostile/logout-response-without-issuer-refused.xml'),
        ));

        // When
        $response = UnverifiedLogoutResponse::of($document);

        // Then
        static::assertSame([null, null], [$response->issuer, $response->inResponseTo]);
    }

    /**
     * Section 5.4: a LogoutRequest is not a LogoutResponse.
     */
    #[Test]
    public function itRefusesAnotherRoot(): void
    {
        // Given
        $document = MetadataFixtures::load('behaviour/logout-request-written-for-http-redirect.xml');

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The root of the message is not a samlp:LogoutResponse (section 5.4).');

        // When
        UnverifiedLogoutResponse::of($document);
    }

    /**
     * Section 5.4, M-6: an InResponseTo that is not an NCName is refused before it names anything; the message carries
     * nothing of it (M-16).
     */
    #[Test]
    public function itRefusesAnInResponseToThatIsNotAnId(): void
    {
        // Given
        $document = SamlLoader::create()->load(str_replace(
            'InResponseTo="' . LogoutFixtures::REQUEST_ID . '"',
            'InResponseTo="1-not-an-ncname"',
            MetadataFixtures::bytes(self::RESPONSE),
        ));

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('An ID is not an NCName (M-6).');

        // When
        UnverifiedLogoutResponse::of($document);
    }
}
