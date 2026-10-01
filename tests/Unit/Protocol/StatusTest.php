<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Protocol;

use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3: the status of a response, its two codes and nothing the peer wrote around them (M-13, M-16).
 */
final class StatusTest extends TestCase
{
    #[Test]
    public function itKeepsItsTwoCodes(): void
    {
        // When
        $status = new Status(StatusCode::Requester, SecondLevelStatusCode::InvalidNameIdPolicy);

        // Then
        static::assertSame(StatusCode::Requester, $status->code);
        static::assertSame(SecondLevelStatusCode::InvalidNameIdPolicy, $status->secondLevel);
    }

    /**
     * SAML Core §3.2.2.2: the second-level code is optional, absent or unknown alike.
     */
    #[Test]
    public function itHasNoSecondLevelCodeUnlessGivenOne(): void
    {
        // When
        $status = new Status(StatusCode::Success);

        // Then
        static::assertNull($status->secondLevel);
    }
}
