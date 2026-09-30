<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Logout;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Particle;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Xml\Core\Children;
use Dom\Element;

/**
 * A samlp:Status read strictly (SAML Core §3.2.2): one samlp:StatusCode, then samlp:StatusMessage and
 * samlp:StatusDetail, neither read (M-13, M-16); the top-level code one of the four of SAML Core (M-5), the second-level
 * one when it has one, an unknown URI reading as null. Each code holds at most one code, and a third-level code is not
 * read.
 *
 * @internal
 */
final readonly class StatusReader
{
    private const string CODE = 'samlp:StatusCode';

    /**
     * The children of samlp:Status, and of its top-level and second-level codes, in the order of the schema.
     *
     * @throws MalformedMessage when they are not a sequence of the schema (M-5)
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
     * The status of a samlp:Status whose structure was checked.
     *
     * @throws MalformedMessage when a code has no Value, or the top-level one is not one of SAML Core's (M-5)
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

    /**
     * The place of a samlp:StatusCode, required once in samlp:Status, optional once in another samlp:StatusCode.
     */
    private static function code(int $min): Particle
    {
        return new Particle(self::CODE, [Schema::samlp('StatusCode')], $min, 1);
    }
}
