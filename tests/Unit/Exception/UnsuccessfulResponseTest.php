<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Exception;

use Beffroi\Saml2\Model\Exception\MessageRefused;
use Beffroi\Saml2\Model\Exception\UnsuccessfulResponse;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use function class_parents;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.8, M-13: a response whose status is not Success yields no assertion, and the refusal carries its status.
 */
final class UnsuccessfulResponseTest extends TestCase
{
    #[Test]
    public function itIsAMessageRefused(): void
    {
        // When / Then
        static::assertContains(MessageRefused::class, class_parents(UnsuccessfulResponse::class));
    }

    /**
     * M-13: the consumer reads both codes of a failure, Responder / AuthnFailed, from the refusal.
     */
    #[Test]
    public function itCarriesTheStatusOfTheResponse(): void
    {
        // Given
        $status = new Status(StatusCode::Responder, SecondLevelStatusCode::AuthnFailed);

        // When
        $refusal = new UnsuccessfulResponse($status);

        // Then
        static::assertSame($status, $refusal->status);
    }

    /**
     * M-16: the message names the rule, the same whatever the codes, which the consumer reads from the status.
     */
    #[Test]
    #[DataProvider('provideFailures')]
    public function itsMessageNamesTheRuleAndNoCode(Status $status): void
    {
        // When
        $refusal = new UnsuccessfulResponse($status);

        // Then
        static::assertSame(
            'The status of the response is not Success, and the response yields no assertion (M-13).',
            $refusal->getMessage(),
        );
    }

    /**
     * @return iterable<string, array{Status}>
     */
    public static function provideFailures(): iterable
    {
        yield 'requester' => [new Status(StatusCode::Requester)];
        yield 'responder, authentication failed' => [
            new Status(StatusCode::Responder, SecondLevelStatusCode::AuthnFailed),
        ];
        yield 'version mismatch, too high' => [
            new Status(StatusCode::VersionMismatch, SecondLevelStatusCode::RequestVersionTooHigh),
        ];
    }

    /**
     * Section 5.8: a Success status is no refusal; building one is a programming error of the caller.
     */
    #[Test]
    #[DataProvider('provideSuccesses')]
    public function itRefusesASuccessStatus(Status $status): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A response refused as unsuccessful has a status other than Success (M-13).');

        // When
        new UnsuccessfulResponse($status);
    }

    /**
     * @return iterable<string, array{Status}>
     */
    public static function provideSuccesses(): iterable
    {
        yield 'success' => [new Status(StatusCode::Success)];
        yield 'success, partial logout' => [new Status(StatusCode::Success, SecondLevelStatusCode::PartialLogout)];
    }
}
