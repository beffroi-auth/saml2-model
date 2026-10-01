<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\AuthnRequest;

use Beffroi\Saml2\Model\Internal\AuthnRequest\AuthnRequestContext;
use Beffroi\Saml2\Model\Tests\Unit\Validation\AuthnRequestFixtures;
use Beffroi\Saml2\Model\Validation\Authentication;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.2 steps 3 to 5: what the rules of an AuthnRequest are checked against, as the validator states it.
 */
final class AuthnRequestContextTest extends TestCase
{
    #[Test]
    public function itHoldsWhatTheValidatorStates(): void
    {
        // Given
        $latest = new DateTimeImmutable('2026-10-01T12:03:00Z');
        $oldest = new DateTimeImmutable('2026-10-01T11:55:00Z');
        $sp = AuthnRequestFixtures::serviceProvider();
        $idp = AuthnRequestFixtures::identityProvider();

        // When
        $context = new AuthnRequestContext(
            $latest,
            $oldest,
            $sp,
            $idp,
            AuthnRequestFixtures::SINGLE_SIGN_ON,
            Authentication::Binding,
        );

        // Then
        static::assertSame(
            [$latest, $oldest, $sp, $idp, AuthnRequestFixtures::SINGLE_SIGN_ON, Authentication::Binding],
            [
                $context->latest,
                $context->oldest,
                $context->serviceProvider,
                $context->identityProvider,
                $context->receivedAt,
                $context->authentication,
            ],
        );
    }
}
