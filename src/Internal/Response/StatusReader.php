<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Response;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Particle;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use Dom\Element;

/**
 * The samlp:Status of a response (SAML Core §3.2.2, M-5, M-13): one samlp:StatusCode, then an optional
 * samlp:StatusMessage and an optional samlp:StatusDetail, neither read; the top-level code one of the four of SAML
 * Core §3.2.2.2, and the second-level code, at most one, one SAML Core lists or null. Deeper codes are not read.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class StatusReader
{
    /**
     * @throws MalformedMessage when an element is missing, repeated or out of order, a code has no Value, or the
     *                          top-level code is not one of the four (M-4, M-5)
     */
    public static function read(Element $status): Status
    {
        Schema::children($status, 'samlp:Status', [
            Particle::of(self::samlp('StatusCode'), 1, 1),
            Particle::of(self::samlp('StatusMessage'), 0, 1),
            Particle::of(self::samlp('StatusDetail'), 0, 1),
        ]);
        $code = Children::one($status, self::samlp('StatusCode'));
        Schema::children($code, 'samlp:StatusCode', [Particle::of(self::samlp('StatusCode'), 0, 1)]);
        $second = Children::named($code, self::samlp('StatusCode'));

        return new Status(
            StatusCode::fromUri(self::value($code)),
            $second === [] ? null : SecondLevelStatusCode::tryFromUri(self::value($second[0])),
        );
    }

    private static function value(Element $code): string
    {
        return Schema::attribute($code, 'samlp:StatusCode', 'Value');
    }

    private static function samlp(string $local): Name
    {
        return new Name(Saml::PROTOCOL, $local);
    }
}
