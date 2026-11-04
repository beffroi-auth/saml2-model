<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Assertion;

use function array_map;
use Beffroi\Saml2\Model\Assertion\Conditions;
use Beffroi\Saml2\Model\Exception\AudienceMismatch;
use Beffroi\Saml2\Model\Exception\IndeterminateCondition;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Particle;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Value\Counts;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use function count;
use DateTimeImmutable;
use Dom\Element;
use function in_array;
use function sprintf;

/**
 * Section 6.1 step 9
 *
 * Every AudienceRestriction must hold our entity ID (SAML Core §2.5.1.4 as corrected by E46).
 *
 * @internal
 */
final readonly class ConditionsReader
{
    /**
     * @throws Unsupported
     * @throws IndeterminateCondition
     * @throws MalformedMessage
     * @throws LimitExceeded
     * @throws OutsideValidityWindow
     * @throws AudienceMismatch
     */
    public static function read(Element $conditions, AssertionContext $context): Conditions
    {
        Schema::unsupported(
            $conditions,
            [Schema::saml('ProxyRestriction')],
            'The Conditions hold a saml:ProxyRestriction, which the package does not support (section 8).',
        );
        foreach (Children::all($conditions) as $condition) {
            if (! self::understood($condition)) {
                throw new IndeterminateCondition('The Conditions hold a condition the package does not understand, and the assertion is Indeterminate (M-13).');
            }
        }
        $oneTimeUse = Children::named($conditions, Schema::saml('OneTimeUse'));
        if (count($oneTimeUse) > 1) {
            throw new MalformedMessage('The Conditions hold more than one saml:OneTimeUse (M-5).');
        }
        $restrictions = Children::named($conditions, Schema::saml('AudienceRestriction'));
        Counts::check(
            count($restrictions),
            Counts::AUDIENCE_RESTRICTIONS,
            sprintf(
                'The Conditions hold more than %d AudienceRestriction, the bound of section 7 (M-17).',
                Counts::AUDIENCE_RESTRICTIONS,
            ),
        );
        $notBefore = self::time($conditions, 'NotBefore');
        if ($notBefore instanceof DateTimeImmutable && $notBefore > $context->window->latest()) {
            throw new OutsideValidityWindow('The NotBefore of the Conditions is later than now plus the clock skew (M-7).');
        }
        $notOnOrAfter = self::time($conditions, 'NotOnOrAfter');
        if ($notOnOrAfter instanceof DateTimeImmutable && $notOnOrAfter <= $context->window->earliest()) {
            throw new OutsideValidityWindow('The NotOnOrAfter of the Conditions is at or before now minus the clock skew (M-7).');
        }

        return new Conditions(
            $notBefore,
            $notOnOrAfter,
            array_map(static fn (Element $restriction): array => self::audiences(
                $restriction,
                $context,
            ), $restrictions),
            $oneTimeUse !== [],
        );
    }

    private static function understood(Element $condition): bool
    {
        return Schema::saml('AudienceRestriction')->matches($condition) || Schema::saml('OneTimeUse')->matches($condition);
    }

    private static function time(Element $conditions, string $local): ?DateTimeImmutable
    {
        $time = Attributes::optional($conditions, new Name(null, $local));

        return $time === null ? null : Time::read($time);
    }

    /**
     * @return list<string>
     */
    private static function audiences(Element $restriction, AssertionContext $context): array
    {
        $audiences = Children::named($restriction, Schema::saml('Audience'));
        Counts::check(
            count($audiences),
            Counts::AUDIENCES,
            sprintf(
                'An AudienceRestriction holds more than %d Audience, the bound of section 7 (M-17).',
                Counts::AUDIENCES,
            ),
        );
        Schema::children($restriction, 'saml:AudienceRestriction', [Particle::of(
            Schema::saml('Audience'),
            1,
            Particle::UNBOUNDED,
        )]);
        $values = array_map(Text::of(...), $audiences);
        if (! in_array($context->audience, $values, true)) {
            throw new AudienceMismatch('An AudienceRestriction does not hold our entity ID among its audiences (M-8).');
        }

        return $values;
    }
}
