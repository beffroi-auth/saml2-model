<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Writing;

use function array_map;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Internal\Writing\ResponseBuilder;
use Beffroi\Saml2\Model\Protocol\Response;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Tests\Unit\Writing\ResponseWriterFixtures as Fixtures;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.6 step 2, core.md section 6.5, SAML Core §3.2.2: the samlp:Response of the identity provider, built with
 * one prefix per namespace, in the order of the schema, before it is signed.
 */
final class ResponseBuilderTest extends TestCase
{
    private const string PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';

    private const string ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    /**
     * Section 6.6 step 2, core.md section 6.5, SAML Profiles §4.1.4.2 as corrected by E17: the samlp prefix declared
     * on the root, the saml prefix on the Issuer and on the Assertion, which introduce it; the attributes of the
     * response, its Issuer without Format, its Status, then its assertion.
     */
    #[Test]
    public function itBuildsTheResponseWithOnePrefixPerNamespace(): void
    {
        // Given
        $response = Fixtures::response();

        // When
        $root = ResponseBuilder::build($response)->root();

        // Then
        $issuer = Children::one($root, new Name(self::ASSERTION, 'Issuer'));
        static::assertSame(
            [
                'samlp:Response',
                ['samlp' => self::PROTOCOL],
                [
                    'ID' => $response->id,
                    'Version' => '2.0',
                    'IssueInstant' => Fixtures::NOW,
                    'Destination' => Fixtures::ASSERTION_CONSUMER,
                    'InResponseTo' => Fixtures::REQUEST,
                ],
                ['saml:Issuer', 'samlp:Status', 'saml:Assertion'],
                [['saml' => self::ASSERTION], [], ['saml' => self::ASSERTION]],
                [[], Fixtures::IDENTITY_PROVIDER],
            ],
            [
                $root->nodeName,
                Fixtures::declarations($root),
                Fixtures::attributes($root),
                Fixtures::names(Children::all($root)),
                array_map(Fixtures::declarations(...), Children::all($root)),
                [Fixtures::attributes($issuer), Text::of($issuer)],
            ],
        );
    }

    /**
     * SAML Core §3.2.2.2, M-13: a failure carries its top-level code and its second-level one, nested, and no
     * assertion.
     */
    #[Test]
    public function itBuildsAFailureWithItsTwoCodes(): void
    {
        // Given
        $response = Fixtures::failure();

        // When
        $root = ResponseBuilder::build($response)->root();

        // Then
        $code = Children::one(Children::one($root, $this->samlp('Status')), $this->samlp('StatusCode'));
        $second = Children::one($code, $this->samlp('StatusCode'));
        static::assertSame(
            [
                ['saml:Issuer', 'samlp:Status'],
                ['Value' => StatusCode::Responder->value],
                ['Value' => SecondLevelStatusCode::AuthnFailed->value],
                [],
            ],
            [
                Fixtures::names(Children::all($root)),
                Fixtures::attributes($code),
                Fixtures::attributes($second),
                Children::all($second),
            ],
        );
    }

    /**
     * SAML Core §3.2.2.2: a status without second-level code is one samlp:StatusCode, empty.
     */
    #[Test]
    public function itBuildsATopLevelCodeAlone(): void
    {
        // Given
        $response = Fixtures::failure(null);

        // When
        $root = ResponseBuilder::build($response)->root();

        // Then
        $status = Children::one($root, $this->samlp('Status'));
        static::assertSame(
            [['samlp:StatusCode'], []],
            [
                Fixtures::names(Children::all($status)),
                Children::all(Children::one($status, $this->samlp('StatusCode'))),
            ],
        );
    }

    /**
     * SAML Core §3.2.2, M-10: a response without Destination, unsolicited, carries neither attribute.
     */
    #[Test]
    public function itLeavesOutTheDestinationAndTheInResponseToItIsNotGiven(): void
    {
        // Given
        $response = new Response(
            SamlId::generate(),
            new DateTimeImmutable(Fixtures::NOW),
            new Issuer(Fixtures::IDENTITY_PROVIDER),
            null,
            null,
            new Status(StatusCode::Requester),
            null,
        );

        // When
        $root = ResponseBuilder::build($response)->root();

        // Then
        static::assertSame(
            ['ID' => $response->id, 'Version' => '2.0', 'IssueInstant' => Fixtures::NOW],
            Fixtures::attributes($root),
        );
    }

    /**
     * M-15, SAML Core §1.3.3: the IssueInstant is written in UTC to the second, whatever the zone and the fraction of
     * the time it was given.
     */
    #[Test]
    public function itWritesTheIssueInstantInUtcToTheSecond(): void
    {
        // Given
        $response = new Response(
            SamlId::generate(),
            new DateTimeImmutable('2026-10-01T12:00:00.750Z')->setTimezone(new DateTimeZone('Europe/Paris')),
            new Issuer(Fixtures::IDENTITY_PROVIDER),
            Fixtures::ASSERTION_CONSUMER,
            null,
            new Status(StatusCode::Requester),
            null,
        );

        // When
        $root = ResponseBuilder::build($response)->root();

        // Then
        static::assertSame(Fixtures::NOW, $root->getAttribute('IssueInstant'));
    }

    private function samlp(string $local): Name
    {
        return new Name(self::PROTOCOL, $local);
    }
}
