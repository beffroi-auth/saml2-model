<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Protocol;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Particle;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Xml\Core\Children;
use Dom\Element;

/**
 * SAML Core §3.2.2
 *
 * The StatusMessage and the StatusDetail are never read (M-13, M-16).
 *
 * @internal
 */
final readonly class StatusReader
{
    private const string CODE = 'samlp:StatusCode';

    /**
     * @throws MalformedMessage
     */
    public static function structure(Element $status): void
    {
        Schema::children($status, 'samlp:Status', [
            self::code(1),
            new Particle('samlp:StatusMessage', [Schema::samlp('StatusMessage')], 0, 1),
            new Particle('samlp:StatusDetail', [Schema::samlp('StatusDetail')], 0, 1),
        ]);
        $secondLevel = Schema::children(Children::one($status, Schema::samlp('StatusCode')), self::CODE, [
            self::code(0),
        ])[0];
        foreach ($secondLevel as $code) {
            Schema::children($code, self::CODE, [self::code(0)]);
        }
    }

    /**
     * @throws MalformedMessage
     */
    public static function read(Element $status): Status
    {
        $code = Children::one($status, Schema::samlp('StatusCode'));
        $secondLevel = Children::optional($code, Schema::samlp('StatusCode'));

        return new Status(
            StatusCode::fromUri(Schema::attribute($code, self::CODE, 'Value')),
            $secondLevel instanceof Element
                ? SecondLevelStatusCode::tryFromUri(Schema::attribute($secondLevel, self::CODE, 'Value'))
                : null,
        );
    }

    private static function code(int $min): Particle
    {
        return new Particle(self::CODE, [Schema::samlp('StatusCode')], $min, 1);
    }
}
