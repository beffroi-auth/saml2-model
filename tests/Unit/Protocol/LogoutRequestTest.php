<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Protocol;

use function array_fill;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Protocol\LogoutRequest;
use Beffroi\Saml2\Model\Tests\Unit\Validation\LogoutFixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3: a samlp:LogoutRequest, whose values are of their lexical form whoever builds it (M-6, M-15).
 */
final class LogoutRequestTest extends TestCase
{
    /**
     * Section 5.3, SAML Core §3.7.1: the fields the rules of section 6.3 read and the writer writes.
     */
    #[Test]
    public function itKeepsItsFields(): void
    {
        // When
        $request = LogoutFixtures::request();

        // Then
        static::assertSame(
            [
                LogoutFixtures::REQUEST_ID,
                LogoutFixtures::NOW,
                LogoutFixtures::IDP,
                LogoutFixtures::SP_SLO,
                '2026-09-30T12:05:00Z',
                '_7a2f4c1d9e',
                ['_session-1'],
                'urn:oasis:names:tc:SAML:2.0:logout:user',
            ],
            [
                $request->id,
                $request->issueInstant->format('Y-m-d\TH:i:s\Z'),
                $request->issuer->entityId,
                $request->destination,
                $request->notOnOrAfter?->format('Y-m-d\TH:i:s\Z'),
                $request->nameId->value,
                $request->sessionIndexes,
                $request->reason,
            ],
        );
    }

    /**
     * SAML Core §3.7.1: the NotOnOrAfter, the session indexes and the Reason are optional.
     */
    #[Test]
    public function itHasNoExpiryNoSessionIndexAndNoReasonUnlessGivenThem(): void
    {
        // When
        $request = new LogoutRequest(
            LogoutFixtures::REQUEST_ID,
            new DateTimeImmutable(LogoutFixtures::NOW),
            new Issuer(LogoutFixtures::IDP),
            LogoutFixtures::SP_SLO,
            null,
            new NameId('_7a2f4c1d9e'),
        );

        // Then
        static::assertSame([null, [], null], [$request->notOnOrAfter, $request->sessionIndexes, $request->reason]);
    }

    /**
     * M-6, M-15: an ID, a Destination and a Reason that the reader would refuse are refused whoever builds them.
     */
    #[Test]
    #[DataProvider('provideValuesRefused')]
    public function itRefusesAValueNotOfItsLexicalForm(
        string $id,
        string $destination,
        ?string $reason,
        string $message,
    ): void {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);

        // When
        new LogoutRequest(
            $id,
            new DateTimeImmutable(LogoutFixtures::NOW),
            new Issuer(LogoutFixtures::IDP),
            $destination,
            null,
            new NameId('_7a2f4c1d9e'),
            [],
            $reason,
        );
    }

    /**
     * @return iterable<string, array{string, string, ?string, string}>
     */
    public static function provideValuesRefused(): iterable
    {
        yield 'an ID that is not an NCName' => [
            '1-not-an-ncname',
            LogoutFixtures::SP_SLO,
            null,
            'An ID is not an NCName (M-6).',
        ];
        yield 'a relative Destination' => [
            LogoutFixtures::REQUEST_ID,
            '/saml/slo',
            null,
            'A URI is not absolute (M-6).',
        ];
        yield 'a relative Reason' => [
            LogoutFixtures::REQUEST_ID,
            LogoutFixtures::SP_SLO,
            'user',
            'A URI is not absolute (M-6).',
        ];
    }

    /**
     * Section 7, M-17: sixteen session indexes, and not seventeen.
     */
    #[Test]
    public function itHoldsSixteenSessionIndexes(): void
    {
        // When
        $request = LogoutFixtures::request(sessionIndexes: array_fill(0, 16, '_session'));

        // Then
        static::assertCount(16, $request->sessionIndexes);
    }

    /**
     * §9.2 row 36, section 7, M-17: one session index over the bound, whoever builds the request.
     */
    #[Test]
    public function itRefusesSeventeenSessionIndexes(): void
    {
        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('A LogoutRequest names more than 16 session indexes, the bound of section 7 (M-17).');

        // When
        LogoutFixtures::request(sessionIndexes: array_fill(0, 17, '_session'));
    }
}
