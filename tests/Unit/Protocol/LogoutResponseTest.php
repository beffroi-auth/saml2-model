<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Protocol;

use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Protocol\LogoutResponse;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Tests\Unit\Validation\LogoutFixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3: a samlp:LogoutResponse, whose values are of their lexical form whoever builds it (M-6, M-15).
 */
final class LogoutResponseTest extends TestCase
{
    /**
     * Section 5.3, SAML Core §3.7.2: the fields the rules of section 6.4 read and the writer writes.
     */
    #[Test]
    public function itKeepsItsFields(): void
    {
        // When
        $response = LogoutFixtures::response(LogoutFixtures::partialLogout());

        // Then
        static::assertSame(
            [
                LogoutFixtures::RESPONSE_ID,
                LogoutFixtures::NOW,
                LogoutFixtures::SP,
                LogoutFixtures::IDP_SLO_RESPONSE,
                LogoutFixtures::REQUEST_ID,
                StatusCode::Success,
                SecondLevelStatusCode::PartialLogout,
            ],
            [
                $response->id,
                $response->issueInstant->format('Y-m-d\TH:i:s\Z'),
                $response->issuer->entityId,
                $response->destination,
                $response->inResponseTo,
                $response->status->code,
                $response->status->secondLevel,
            ],
        );
    }

    /**
     * M-6, M-15: an ID, a Destination and an InResponseTo that the reader would refuse are refused whoever builds
     * them.
     */
    #[Test]
    #[DataProvider('provideValuesRefused')]
    public function itRefusesAValueNotOfItsLexicalForm(
        string $id,
        string $destination,
        string $inResponseTo,
        string $message,
    ): void {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);

        // When
        new LogoutResponse(
            $id,
            new DateTimeImmutable(LogoutFixtures::NOW),
            new Issuer(LogoutFixtures::SP),
            $destination,
            $inResponseTo,
            new Status(StatusCode::Success),
        );
    }

    /**
     * @return iterable<string, array{string, string, string, string}>
     */
    public static function provideValuesRefused(): iterable
    {
        yield 'an ID that is not an NCName' => [
            '1-not-an-ncname',
            LogoutFixtures::IDP_SLO,
            LogoutFixtures::REQUEST_ID,
            'An ID is not an NCName (M-6).',
        ];
        yield 'a relative Destination' => [
            LogoutFixtures::RESPONSE_ID,
            '/saml/slo',
            LogoutFixtures::REQUEST_ID,
            'A URI is not absolute (M-6).',
        ];
        yield 'an InResponseTo that is not an NCName' => [
            LogoutFixtures::RESPONSE_ID,
            LogoutFixtures::IDP_SLO,
            '1-not-an-ncname',
            'An ID is not an NCName (M-6).',
        ];
    }
}
