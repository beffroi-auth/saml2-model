<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Response;

use Beffroi\Saml2\Model\Exception\DestinationMismatch;
use Beffroi\Saml2\Model\Exception\InResponseToMismatch;
use Beffroi\Saml2\Model\Exception\IssuerMismatch;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Internal\Assertion\AssertionContext;
use Beffroi\Saml2\Model\Internal\Assertion\IssuerReader;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Saml2\Model\Value\Uri;
use Beffroi\Saml2\Model\Value\Version;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Dsig\Verified;
use Dom\Element;

/**
 * Section 6.1 step 6
 *
 * It reads nothing of the assertion, so that it runs before an encrypted one is decrypted.
 *
 * @internal
 */
final readonly class EnvelopeReader
{
    /**
     * @return string the ID of the response
     *
     * @throws MalformedMessage
     * @throws OutsideValidityWindow
     * @throws DestinationMismatch
     * @throws IssuerMismatch
     * @throws InResponseToMismatch
     * @throws MixedContent
     */
    public static function read(SignedResponse $response, AssertionContext $context): string
    {
        $root = $response->root;
        $signed = $response->verification instanceof Verified;
        Version::read(Schema::attribute($root, 'samlp:Response', 'Version'));
        $id = Schema::attribute($root, 'samlp:Response', 'ID');
        $issueInstant = Time::read(Schema::attribute($root, 'samlp:Response', 'IssueInstant'));
        if ($issueInstant > $context->window->latest()) {
            throw new OutsideValidityWindow('The IssueInstant of the response is later than now plus the clock skew (M-7).');
        }
        if ($issueInstant < $context->window->oldest()) {
            throw new OutsideValidityWindow('The IssueInstant of the response is older than maxMessageAge (M-7).');
        }
        $destination = Attributes::optional($root, new Name(null, 'Destination'));
        if ($destination === null && $signed) {
            throw new DestinationMismatch('The response is signed and has no Destination (M-8).');
        }
        if ($destination !== null && Uri::read($destination) !== $context->recipient) {
            throw new DestinationMismatch('The Destination of the response is not the URL at which it arrived (M-8).');
        }
        $issuer = Children::optional($root, Schema::saml('Issuer'));
        if (! $issuer instanceof Element && $signed) {
            throw new MalformedMessage('The response is signed and has no saml:Issuer (M-8).');
        }
        if ($issuer instanceof Element) {
            IssuerReader::read($issuer, $context->identityProvider);
        }
        $inResponseTo = Attributes::optional($root, new Name(null, 'InResponseTo'));
        if ($inResponseTo !== null) {
            SamlId::read($inResponseTo);
        }
        if ($inResponseTo !== $context->inResponseTo) {
            throw new InResponseToMismatch('The InResponseTo of the response is not the one the consumer expects (M-10).');
        }

        return $id;
    }
}
