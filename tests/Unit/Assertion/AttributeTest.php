<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Assertion;

use function array_fill;
use Beffroi\Saml2\Model\Assertion\Attribute;
use Beffroi\Saml2\Model\Assertion\AttributeNameFormat;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3, section 6.1 step 11: an attribute as read, its values as text (SAML Core §2.7.3.1).
 */
final class AttributeTest extends TestCase
{
    /**
     * Section 6.1 step 11: the name, the format, the friendly name and the values in their order, kept as given.
     */
    #[Test]
    public function itKeepsItsNameFormatFriendlyNameAndValues(): void
    {
        // When
        $attribute = new Attribute(
            'urn:oid:1.3.6.1.4.1.5923.1.1.1.1',
            AttributeNameFormat::Uri,
            'eduPersonAffiliation',
            [
                'member',
                'student',
            ],
        );

        // Then
        static::assertSame(
            [
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.1',
                AttributeNameFormat::Uri,
                'eduPersonAffiliation',
                ['member', 'student'],
            ],
            [$attribute->name, $attribute->nameFormat, $attribute->friendlyName, $attribute->values],
        );
    }

    /**
     * Section 7, M-15, M-17: 256 values, the bound the reader of the service provider applies.
     */
    #[Test]
    public function itHoldsTheValuesOfItsBound(): void
    {
        // Given
        $values = array_fill(0, 256, 'member');

        // When
        $attribute = new Attribute('uid', AttributeNameFormat::Unspecified, null, $values);

        // Then
        static::assertSame($values, $attribute->values);
    }

    /**
     * §9.2 row 36, M-15, M-17: 257 values, which the reader of the service provider would refuse, are refused whoever
     * builds the attribute, a writer included.
     */
    #[Test]
    public function itRefusesValuesOverTheirBound(): void
    {
        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('An Attribute holds more than 256 AttributeValue, the bound of section 7 (M-17).');

        // When
        new Attribute('uid', AttributeNameFormat::Unspecified, null, array_fill(0, 257, 'member'));
    }
}
