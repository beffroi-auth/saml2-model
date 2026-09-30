<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Validation;

use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.5, M-8, M-10: what the consumer expects of a response.
 */
final class ExpectedResponseTest extends TestCase
{
    /**
     * M-10, SAML Profiles §4.1.4.3: an answer to a request names it, with the URL of arrival and our entity ID.
     */
    #[Test]
    public function itExpectsAnAnswerToTheRequestItNames(): void
    {
        // When
        $expected = ExpectedResponse::toRequest(
            '_request',
            'https://sp.example.com/saml/acs',
            'https://sp.example.com/saml',
        );

        // Then
        static::assertSame(
            ['_request', 'https://sp.example.com/saml/acs', 'https://sp.example.com/saml'],
            [$expected->requestId, $expected->receivedAt, $expected->audience],
        );
    }

    /**
     * M-10, SAML Profiles §4.1.5: an unsolicited response answers no request.
     */
    #[Test]
    public function itExpectsAnUnsolicitedResponseToAnswerNoRequest(): void
    {
        // When
        $expected = ExpectedResponse::unsolicited('https://sp.example.com/saml/acs', 'https://sp.example.com/saml');

        // Then
        static::assertSame(
            [null, 'https://sp.example.com/saml/acs', 'https://sp.example.com/saml'],
            [$expected->requestId, $expected->receivedAt, $expected->audience],
        );
    }
}
