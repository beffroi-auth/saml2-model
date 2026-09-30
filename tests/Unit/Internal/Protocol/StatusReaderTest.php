<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Protocol;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Protocol\StatusReader;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion\AssertionFixtures;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Name;
use Dom\Element;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * M-5, M-13, SAML Core §3.2.2: the status of a response or a logout response, its two codes, and nothing the peer wrote
 * around them.
 */
final class StatusReaderTest extends TestCase
{
    use AssertionFixtures;

    /**
     * §9.3 row 14, SAML Core §3.2.2.2: the top-level code and the second-level one; the StatusMessage and the
     * StatusDetail are not read.
     */
    #[Test]
    public function itReadsBothCodes(): void
    {
        // Given
        $status = $this->statusOf($this->document('behaviour/response-status-responder-authn-failed-refused.xml'));

        // When
        $read = StatusReader::read($status);

        // Then
        static::assertSame([StatusCode::Responder, SecondLevelStatusCode::AuthnFailed], [
            $read->code,
            $read->secondLevel,
        ]);
    }

    /**
     * SAML Core §3.2.2.2: without a second-level code, or with one SAML Core does not list, the second level is null.
     */
    #[Test]
    #[DataProvider('provideStatusesWithoutAKnownSecondLevel')]
    public function itReadsNoSecondLevelCodeItDoesNotKnow(string $fixture, StatusCode $code): void
    {
        // Given
        $status = $this->statusOf($this->document($fixture));

        // When
        $read = StatusReader::read($status);

        // Then
        static::assertSame([$code, null], [$read->code, $read->secondLevel]);
    }

    /**
     * @return iterable<string, array{string, StatusCode}>
     */
    public static function provideStatusesWithoutAKnownSecondLevel(): iterable
    {
        yield 'none' => ['behaviour/response-status-requester-without-issuer-refused.xml', StatusCode::Requester];
        yield 'an unknown one' => [
            'behaviour/response-status-responder-unknown-second-level-refused.xml',
            StatusCode::Responder,
        ];
    }

    /**
     * M-4, M-5, SAML Core §3.2.2.2: a top-level code of no SAML Core vocabulary, a code without Value, the
     * StatusMessage before the StatusCode, two second-level codes, two third-level codes.
     */
    #[Test]
    #[DataProvider('provideMalformedStatuses')]
    public function itRefusesAMalformedStatus(string $fixture, string $message): void
    {
        // Given
        $document = $this->document($fixture);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);
        self::assertCarriesNothingOf($message, $document);

        // When
        $this->readChecked($this->statusOf($document));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMalformedStatuses(): iterable
    {
        yield 'an unknown top-level code' => [
            'hostile/response-status-unknown-code-refused.xml',
            'The top-level status code is not one of the four of SAML Core (M-5).',
        ];
        yield 'a top-level code without Value' => [
            'hostile/response-status-code-without-value-refused.xml',
            'The samlp:StatusCode has no Value (M-5).',
        ];
        yield 'a second-level code without Value' => [
            'hostile/response-status-second-level-without-value-refused.xml',
            'The samlp:StatusCode has no Value (M-5).',
        ];
        yield 'the StatusMessage before the StatusCode' => [
            'hostile/response-status-message-before-code-refused.xml',
            'The samlp:Status holds a child out of the order of the schema, or one it does not allow there (M-5).',
        ];
        yield 'two second-level codes' => [
            'hostile/response-status-two-second-level-codes-refused.xml',
            'The samlp:StatusCode holds more than one samlp:StatusCode (M-4).',
        ];
        yield 'two third-level codes' => [
            'hostile/logout-response-two-third-level-status-codes-refused.xml',
            'The samlp:StatusCode holds more than one samlp:StatusCode (M-4).',
        ];
    }

    /**
     * The structure of the status checked, then its values read, as the envelope of a response reads it.
     */
    private function readChecked(Element $status): void
    {
        StatusReader::structure($status);
        StatusReader::read($status);
    }

    private function statusOf(Document $document): Element
    {
        return Children::one($document->root(), new Name(Saml::PROTOCOL, 'Status'));
    }
}
