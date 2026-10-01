<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Response;

use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion\AssertionFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;

/**
 * The response fixtures of tests/Fixture/ (tests/Support/ResponseFixtureBuilder.php) and the identity provider they
 * come from, https://idp.example.com/saml, whose metadata lists the identity provider's test key; the response answers
 * _request at https://sp.example.com/saml/acs for https://sp.example.com/saml, a second before the frozen clock of
 * AssertionFixtures.
 */
trait ResponseFixtures
{
    use AssertionFixtures;

    /**
     * The metadata of an identity provider, its signing key the test key $key (M-3): the identity provider's by
     * default, the service provider's for a key the identity provider never signed with.
     *
     * @param 'idp'|'sp' $key
     */
    private static function identityProvider(
        string $entityId = 'https://idp.example.com/saml',
        string $key = 'idp',
    ): IdentityProvider {
        return new IdentityProvider(
            $entityId,
            [MetadataFixtures::certificate($key)],
            [],
            [new Endpoint(Binding::HttpRedirect, 'https://idp.example.com/saml/sso')],
        );
    }

    /**
     * The response of $fixture as the consumer receives it (section 5.4).
     */
    private function unverified(string $fixture): UnverifiedResponse
    {
        return UnverifiedResponse::of($this->document($fixture));
    }
}
