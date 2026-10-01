<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Protocol;

use function array_map;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Protocol\AuthnContextComparison;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3, M-5: the comparison of a requested authentication context, a closed vocabulary (SAML Core
 * §3.3.2.2.1).
 */
final class AuthnContextComparisonTest extends TestCase
{
    /**
     * SAML Core §3.3.2.2.1: the four values of AuthnContextComparisonType, and no other.
     */
    #[Test]
    public function itHoldsTheFourComparisonsOfSamlCore(): void
    {
        // When
        $values = array_map(
            static fn (AuthnContextComparison $comparison): string => $comparison->value,
            AuthnContextComparison::cases(),
        );

        // Then
        static::assertSame(['exact', 'minimum', 'maximum', 'better'], $values);
    }

    #[Test]
    #[DataProvider('provideComparisons')]
    public function itReadsEachComparisonFromItsAttribute(AuthnContextComparison $comparison): void
    {
        // When / Then
        static::assertSame($comparison, AuthnContextComparison::fromAttribute($comparison->value));
    }

    /**
     * @return iterable<string, array{AuthnContextComparison}>
     */
    public static function provideComparisons(): iterable
    {
        foreach (AuthnContextComparison::cases() as $comparison) {
            yield $comparison->name => [$comparison];
        }
    }

    /**
     * SAML Core §3.3.2.2.1: "If Comparison is omitted, then exact is used."
     */
    #[Test]
    public function itReadsAnAbsentComparisonAsExact(): void
    {
        // When / Then
        static::assertSame(AuthnContextComparison::Exact, AuthnContextComparison::fromAttribute(null));
    }

    /**
     * M-5, M-6: any other value is refused, compared as a string, and the refusal carries none of it (M-16).
     */
    #[Test]
    #[DataProvider('provideRefusedValues')]
    public function itRefusesEveryOtherValue(string $value): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The Comparison of a samlp:RequestedAuthnContext is not one of exact, minimum, maximum and better (M-5).');

        // When
        AuthnContextComparison::fromAttribute($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRefusedValues(): iterable
    {
        yield 'another case' => ['Exact'];
        yield 'surrounded by whitespace' => [' minimum'];
        yield 'empty' => [''];
        yield 'a value of its own' => ['stronger'];
    }
}
