<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Logout;

use Beffroi\Saml2\Model\Exception\DestinationMismatch;
use Beffroi\Saml2\Model\Exception\InResponseToMismatch;
use Beffroi\Saml2\Model\Exception\IssuerMismatch;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Internal\Particle;
use Beffroi\Saml2\Model\Internal\Protocol\StatusReader;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Protocol\LogoutResponse;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use Dom\Element;

/**
 * Section 6.4
 *
 * @internal
 */
final readonly class LogoutResponseReader
{
    private const string ELEMENT = 'samlp:LogoutResponse';

    /**
     * @throws MalformedMessage
     */
    public static function structure(Element $root): void
    {
        [$status] = Envelope::children($root, self::ELEMENT, 'Profiles §4.4.4.2', [
            new Particle('samlp:Status', [Schema::samlp('Status')], 1, 1),
        ]);
        StatusReader::structure($status[0]);
    }

    /**
     * Section 6.4, M-1
     *
     * A status other than Success, a partial logout included, is an answer and not a refusal.
     *
     * @throws IssuerMismatch
     * @throws MalformedMessage
     * @throws OutsideValidityWindow
     * @throws DestinationMismatch
     * @throws InResponseToMismatch
     * @throws MixedContent
     */
    public static function read(Element $root, LogoutContext $context, string $requestId): LogoutResponse
    {
        [$id, $issueInstant, $issuer, $destination] = Envelope::header($root, self::ELEMENT, $context);
        $inResponseTo = Attributes::optional($root, new Name(null, 'InResponseTo'));
        if ($inResponseTo !== $requestId) {
            throw new InResponseToMismatch('The InResponseTo of the LogoutResponse is not the ID of the LogoutRequest the consumer names (M-10).');
        }

        return new LogoutResponse(
            $id,
            $issueInstant,
            $issuer,
            $destination,
            $inResponseTo,
            StatusReader::read(Children::one($root, Schema::samlp('Status'))),
        );
    }
}
