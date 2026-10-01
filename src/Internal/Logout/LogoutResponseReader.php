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
 * A samlp:LogoutResponse in the order of section 6.4: its structure before any signature, then its values from what
 * the signature or the binding authenticated (M-1).
 *
 * @internal
 */
final readonly class LogoutResponseReader
{
    private const string ELEMENT = 'samlp:LogoutResponse';

    /**
     * Section 6.4, before any signature: saml:Issuer, required (SAML Profiles §4.4.4.2), ds:Signature,
     * samlp:Extensions, then samlp:Status and its codes.
     *
     * @throws MalformedMessage when the children are not a sequence of the schema, or the Issuer is missing (M-5)
     */
    public static function structure(Element $root): void
    {
        [$status] = Envelope::children($root, self::ELEMENT, 'Profiles §4.4.4.2', [
            new Particle('samlp:Status', [Schema::samlp('Status')], 1, 1),
        ]);
        StatusReader::structure($status[0]);
    }

    /**
     * Section 6.4, on the root of what the signature or the binding authenticated, whose structure was checked: the
     * header of the envelope, the InResponseTo of the request the consumer names (M-10), and the status, whichever it
     * is: a status other than Success, a partial logout included, is an answer and not a refusal.
     *
     * @param string $requestId the ID of the LogoutRequest the response answers
     *
     * @throws IssuerMismatch when the Issuer is not the peer's (M-8)
     * @throws MalformedMessage when an attribute is absent or not of its lexical form, or the top-level status code is
     *                          not one of SAML Core's (M-5, M-6)
     * @throws OutsideValidityWindow when the IssueInstant is outside its window (M-7)
     * @throws DestinationMismatch when the Destination is not the URL of arrival, one of ours (M-8)
     * @throws InResponseToMismatch when the InResponseTo is absent or names another request (M-10)
     * @throws MixedContent when the Issuer holds an element
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
