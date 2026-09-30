<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Writing;

use function array_map;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Validation\LogoutFixtures;
use Beffroi\Saml2\Model\Writing\LogoutResponseWriter;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use Dom\Element;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Sections 5.7 and 6.6, M-15: a samlp:LogoutResponse written, signed for HTTP-POST or not for HTTP-Redirect.
 */
final class LogoutResponseWriterTest extends TestCase
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * Section 6.6, M-15, SAML Core §3.2.1, §5.4.1: the Signature is enveloped after the Issuer, over the ID of the
     * response, before the Status; the prefixes are samlp and saml.
     */
    #[Test]
    public function itSignsAfterTheIssuer(): void
    {
        // When
        $root = new LogoutResponseWriter()
            ->write(
                LogoutFixtures::response(),
                new Signing(MetadataFixtures::signingKey('sp')),
            )
            ->root();

        // Then
        $reference = Children::one(
            Children::one(Children::one($root, new Name(self::DSIG, 'Signature')), new Name(self::DSIG, 'SignedInfo')),
            new Name(self::DSIG, 'Reference'),
        );
        static::assertSame(
            [
                ['saml:Issuer', 'ds:Signature', 'samlp:Status'],
                '#' . LogoutFixtures::RESPONSE_ID,
                'samlp:LogoutResponse',
            ],
            [
                array_map(static fn (Element $child): string => $child->nodeName, Children::all($root)),
                Attributes::required($reference, new Name(null, 'URI')),
                $root->nodeName,
            ],
        );
    }

    /**
     * Section 6.8, SAML Bindings §3.4.4.1: for HTTP-Redirect the response carries no ds:Signature.
     */
    #[Test]
    public function itWritesNoSignatureForHttpRedirect(): void
    {
        // When
        $root = new LogoutResponseWriter()
            ->write(LogoutFixtures::response(), null)
            ->root();

        // Then
        static::assertSame([], Children::named($root, new Name(self::DSIG, 'Signature')));
    }
}
