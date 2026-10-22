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
 * The envelope of a response, section 6.1 step 6, read from the verified response when it was signed and from the
 * received one otherwise (step 3): Version 2.0, an ID (an NCName, which the loader checked, I-8), an IssueInstant
 * neither later than now plus the skew nor older than maxMessageAge (M-7); a Destination required when the response is
 * signed and equal to the URL of arrival whenever present (M-8, SAML Bindings §3.5.5.2, SAML Core §3.2.1); an Issuer
 * required when the response is signed or holds a saml:EncryptedAssertion (SAML Profiles §4.1.4.2 as corrected by
 * E17) and the identity provider's entity ID whenever present (M-8); the InResponseTo the consumer expects, or none
 * for an unsolicited response (M-10). The context is the assertion's, whose URL of arrival is the response's too.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class EnvelopeReader
{
    /**
     * @return string the ID of the response
     *
     * @throws MalformedMessage when an attribute is absent or not of its lexical form (M-5, M-6), or a signed response,
     *                          or one holding a saml:EncryptedAssertion, has no Issuer (M-8)
     * @throws OutsideValidityWindow when the IssueInstant is ahead, or too old (M-7)
     * @throws DestinationMismatch when the Destination is not the URL of arrival, or a signed response has none (M-8)
     * @throws IssuerMismatch when the Issuer is not the identity provider's (M-8)
     * @throws InResponseToMismatch when the InResponseTo is not the one expected (M-10)
     * @throws MixedContent when the Issuer holds an element
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
        if (! $issuer instanceof Element && Children::optional($root, Schema::saml('EncryptedAssertion')) instanceof Element) {
            throw new MalformedMessage('The response holds a saml:EncryptedAssertion and has no saml:Issuer (M-8).');
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
