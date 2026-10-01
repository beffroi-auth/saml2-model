<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Validation;

use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Validation\AcceptedAuthnRequest;
use Beffroi\Saml2\Model\Validation\Authentication;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.6: what the identity provider accepted, the request, the endpoint of M-9 and how it was authenticated.
 */
final class AcceptedAuthnRequestTest extends TestCase
{
    #[Test]
    public function itHoldsTheRequestItsEndpointAndItsAuthentication(): void
    {
        // Given
        $request = new AuthnRequest(
            AuthnRequestFixtures::ID,
            new DateTimeImmutable(AuthnRequestFixtures::NOW),
            new Issuer(AuthnRequestFixtures::SERVICE_PROVIDER),
        );
        $endpoint = new IndexedEndpoint(Binding::HttpPost, AuthnRequestFixtures::ASSERTION_CONSUMER, 0);

        // When
        $accepted = new AcceptedAuthnRequest($request, $endpoint, Authentication::None);

        // Then
        static::assertSame([$request, $endpoint, Authentication::None], [
            $accepted->request,
            $accepted->assertionConsumerService,
            $accepted->authentication,
        ]);
    }
}
