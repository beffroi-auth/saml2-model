<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Metadata;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3: an endpoint, its binding and its two locations, URIs of M-6 (SAML Metadata §2.2.2).
 */
final class EndpointTest extends TestCase
{
    /**
     * Section 5.3: the binding, the location and the response location, kept as given.
     */
    #[Test]
    public function itKeepsItsBindingAndLocations(): void
    {
        // When
        $endpoint = new Endpoint(
            Binding::HttpRedirect,
            'https://idp.example.com/slo',
            'https://idp.example.com/slo/response',
        );

        // Then
        static::assertSame(
            [Binding::HttpRedirect, 'https://idp.example.com/slo', 'https://idp.example.com/slo/response'],
            [$endpoint->binding, $endpoint->location, $endpoint->responseLocation],
        );
    }

    /**
     * SAML Metadata §2.2.2: the response location is optional.
     */
    #[Test]
    public function itHasNoResponseLocationByDefault(): void
    {
        // When
        $endpoint = new Endpoint(Binding::HttpPost, 'https://idp.example.com/sso');

        // Then
        static::assertNull($endpoint->responseLocation);
    }

    /**
     * M-6, section 6.5 step 6: the location is an absolute URI.
     */
    #[Test]
    public function itRefusesARelativeLocation(): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A URI is not absolute (M-6).');

        // When
        new Endpoint(Binding::HttpPost, '/sso');
    }

    /**
     * M-6: the response location is an absolute URI too.
     */
    #[Test]
    public function itRefusesARelativeResponseLocation(): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A URI is not absolute (M-6).');

        // When
        new Endpoint(Binding::HttpRedirect, 'https://idp.example.com/slo', 'slo/response');
    }
}
