<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Response;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Internal\Assertion\AssertionContext;
use Beffroi\Saml2\Model\Internal\Response\EnvelopeReader;
use Beffroi\Saml2\Model\Internal\Response\SignedResponse;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\TimeBounds;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.1 step 6, M-6, M-7, M-8, M-10: the envelope of a response, its lexical forms and its window; the rules the
 * corpus of §9.2 names are the tests of ResponseValidatorTest.
 */
final class EnvelopeReaderTest extends TestCase
{
    use ResponseFixtures;

    /**
     * Section 5.5: the ID of the response, as read.
     */
    #[Test]
    public function itReturnsTheIdOfTheResponse(): void
    {
        // Given
        $response = $this->signedResponse('behaviour/response-signed-both-accepted.xml');

        // When
        $id = EnvelopeReader::read($response, $this->context());

        // Then
        static::assertSame('_response', $id);
    }

    /**
     * M-7: an IssueInstant at now plus the skew, and one exactly maxMessageAge old, are inside the window.
     */
    #[Test]
    #[DataProvider('provideEdgesOfTheWindow')]
    public function itAcceptsAnIssueInstantAtTheEdgesOfTheWindow(string $now): void
    {
        // Given
        $response = $this->signedResponse('behaviour/response-signed-both-accepted.xml');

        // When
        $id = EnvelopeReader::read($response, $this->contextAt($now));

        // Then
        static::assertSame('_response', $id);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideEdgesOfTheWindow(): iterable
    {
        yield 'issued at now plus the skew' => ['2026-09-30T11:56:59Z'];
        yield 'issued maxMessageAge ago' => ['2026-09-30T12:04:59Z'];
    }

    /**
     * §9.2 row 18, M-7: an IssueInstant later than now plus the skew; a response older than maxMessageAge.
     */
    #[Test]
    #[DataProvider('provideInstantsOutsideTheWindow')]
    public function itRefusesAnIssueInstantOutsideTheWindow(string $now, string $message): void
    {
        // Given
        $response = $this->signedResponse('behaviour/response-signed-both-accepted.xml');

        // Then
        $this->expectException(OutsideValidityWindow::class);
        $this->expectExceptionMessageIs($message);

        // When
        EnvelopeReader::read($response, $this->contextAt($now));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideInstantsOutsideTheWindow(): iterable
    {
        yield 'a second beyond now plus the skew' => [
            '2026-09-30T11:56:58Z',
            'The IssueInstant of the response is later than now plus the clock skew (M-7).',
        ];
        yield 'a second older than maxMessageAge' => [
            '2026-09-30T12:05:00Z',
            'The IssueInstant of the response is older than maxMessageAge (M-7).',
        ];
    }

    /**
     * §9.2 rows 25 and 26, M-5, M-6: a Version other than 2.0, no Version, no ID, no IssueInstant, an InResponseTo that
     * is not an NCName, a relative Destination.
     */
    #[Test]
    #[DataProvider('provideEnvelopesNotOfTheirForm')]
    public function itRefusesAnEnvelopeNotOfItsForm(string $fixture, string $message): void
    {
        // Given
        $response = $this->signedResponse($fixture);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);

        // When
        EnvelopeReader::read($response, $this->context());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideEnvelopesNotOfTheirForm(): iterable
    {
        yield 'Version 2.1' => ['hostile/response-version-2-1-refused.xml', 'The version is not 2.0 (M-6).'];
        yield 'no Version' => [
            'hostile/response-without-version-refused.xml',
            'The samlp:Response has no Version (M-5).',
        ];
        yield 'no ID' => ['hostile/response-without-id-refused.xml', 'The samlp:Response has no ID (M-5).'];
        yield 'no IssueInstant' => [
            'hostile/response-without-issue-instant-refused.xml',
            'The samlp:Response has no IssueInstant (M-5).',
        ];
        yield 'an InResponseTo that is not an NCName' => [
            'hostile/response-in-response-to-not-an-ncname-refused.xml',
            'An ID is not an NCName (M-6).',
        ];
        yield 'a relative Destination' => [
            'hostile/response-destination-relative-refused.xml',
            'A URI is not absolute (M-6).',
        ];
    }

    /**
     * The response of $fixture, verified when it is signed; the received Document is held while it is verified, since
     * Core finds the document of an element through it.
     */
    private function signedResponse(string $fixture): SignedResponse
    {
        $document = $this->document($fixture);

        return SignedResponse::of($document->root(), self::identityProvider(), SamlLoader::create());
    }

    /**
     * The context of the valid response, at $now.
     */
    private function contextAt(string $now): AssertionContext
    {
        return new AssertionContext(
            new DateTimeImmutable($now),
            new TimeBounds(),
            'https://idp.example.com/saml',
            'https://sp.example.com/saml',
            'https://sp.example.com/saml/acs',
            '_request',
        );
    }
}
