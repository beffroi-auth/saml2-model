<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Assertion;

use Beffroi\Saml2\Model\Assertion\Attribute;
use Beffroi\Saml2\Model\Assertion\AttributeNameFormat;
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
}
