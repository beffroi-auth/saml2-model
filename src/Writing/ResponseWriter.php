<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Writing;

use Beffroi\Saml2\Model\Assertion\Assertion;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Writing\ResponseBuilder;
use Beffroi\Saml2\Model\Protocol\Response;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Dsig\Exception\SigningFailed;
use Beffroi\Xml\Dsig\Signer;
use DateTimeImmutable;
use InvalidArgumentException;
use SensitiveParameter;

/**
 * A samlp:Response of the Web Browser SSO profile written by the identity provider, in the order of section 6.6
 * (section 5.7, M-15). First checked against what the validator of the service provider refuses of the objects
 * together, each object having checked its own values: a window that ends before it starts and Conditions without
 * AudienceRestriction are the refusals of Conditions itself, with the exception of their rule (section 5.8); what
 * only the writer sees is a programming error of the caller, \InvalidArgumentException, before anything is built.
 * Then built with DocumentFactory and one prefix per namespace, samlp and saml, its Issuer and its Destination always
 * written (E17, SAML Bindings §3.5.5.2), times in UTC to the second, IDs the objects carry, drawn by SamlId::generate();
 * then signed through Dsig's Signer with SamlLoader::create(), the Signature after the saml:Issuer (SAML Core §2.3.3,
 * §3.2.1, §5.4.1) and no InclusiveNamespaces prefix list (dsig.md section 6.2): the assertion first, then, for
 * SignedParts::AssertionAndResponse, the response over the document the first call returned, so that the response's
 * digest covers the assertion's Signature (dsig.md section 5.5).
 */
final readonly class ResponseWriter
{
    /**
     * The response with its assertion, the assertion signed, the response signed over it on request.
     *
     * @throws InvalidArgumentException when the response carries no assertion, a failure being writeFailure()'s, or the
     *                                   response and its assertion would be refused together (section 6.6 step 1): a
     *                                   programming error of the caller (section 5.8)
     * @throws MalformedMessage when a time is not of a four-digit year (M-15)
     * @throws RefusedXml what Core's serializer and loader and Dsig refuse while signing
     * @throws SigningFailed when the signing key fails
     */
    public function write(
        Response $response,
        #[SensitiveParameter]
        Signing $signing,
        SignedParts $parts = SignedParts::Assertion,
    ): Document {
        $assertion =
            $response->assertion ?? throw new InvalidArgumentException('The response carries no assertion: a failure is written by writeFailure() (section 6.6).');
        $this->checkDestination($response);
        $this->check($response, $assertion);
        $signer = new Signer(SamlLoader::create());
        $signed = $this->sign($signer, ResponseBuilder::build($response), $assertion->id, $signing);
        if ($parts === SignedParts::Assertion) {
            return $signed;
        }

        return $this->sign($signer, $signed, $response->id, $signing);
    }

    /**
     * A response whose status is not Success, without assertion (SAML Profiles §4.1.4.1, M-13), signed when $signing
     * is given.
     *
     * @throws InvalidArgumentException when the response carries an assertion, its status being Success, or holds no
     *                                   Destination: a programming error of the caller (section 5.8)
     * @throws MalformedMessage when the IssueInstant is not of a four-digit year (M-15)
     * @throws RefusedXml what Core's serializer and loader and Dsig refuse while signing
     * @throws SigningFailed when the signing key fails
     */
    public function writeFailure(
        Response $response,
        #[SensitiveParameter]
        ?Signing $signing,
    ): Document {
        if ($response->assertion instanceof Assertion) {
            throw new InvalidArgumentException('The response carries an assertion: a response whose status is Success is written by write() (section 6.6).');
        }
        $this->checkDestination($response);
        $document = ResponseBuilder::build($response);
        if (! $signing instanceof Signing) {
            return $document;
        }

        return $this->sign(new Signer(SamlLoader::create()), $document, $response->id, $signing);
    }

    /**
     * Section 6.6 step 1: the Destination always written, which the service provider requires of a signed response
     * (M-8, SAML Bindings §3.5.5.2).
     *
     * @throws InvalidArgumentException
     */
    private function checkDestination(Response $response): void
    {
        if ($response->destination === null) {
            throw new InvalidArgumentException('The response holds no Destination, which the writer always writes and the service provider requires of a signed response (section 6.6).');
        }
    }

    /**
     * Section 6.6 step 1: what the validator of the service provider refuses of the response and its assertion
     * together, in the order of section 6.1.
     *
     * @throws InvalidArgumentException
     * @throws MalformedMessage
     */
    private function check(Response $response, Assertion $assertion): void
    {
        if ($assertion->id === $response->id) {
            throw new InvalidArgumentException('The response and its assertion carry the same ID, which one ID space refuses (M-14).');
        }
        if ($assertion->issuer->entityId !== $response->issuer->entityId) {
            throw new InvalidArgumentException('The response and its assertion name different issuers, which the service provider compares with one entity ID (M-8).');
        }
        if ($assertion->confirmation->recipient !== $response->destination) {
            throw new InvalidArgumentException('The Recipient of the bearer confirmation is not the Destination of the response, which the service provider compares with one URL (M-8).');
        }
        if ($assertion->confirmation->inResponseTo !== $response->inResponseTo) {
            throw new InvalidArgumentException('The InResponseTo of the bearer confirmation is not the one of the response, which the service provider compares with one request (M-10).');
        }
        if ($assertion->authnStatement->sessionIndex === null) {
            throw new InvalidArgumentException('The authentication statement holds no SessionIndex, which the Single Logout profile needs (section 6.6).');
        }
        $conditions = $assertion->conditions;
        if (
            $conditions->notBefore instanceof DateTimeImmutable
            && $conditions->notOnOrAfter instanceof DateTimeImmutable
            && $this->written($conditions->notBefore) >= $this->written($conditions->notOnOrAfter)
        ) {
            throw new InvalidArgumentException('The NotBefore of the Conditions is not earlier than their NotOnOrAfter, to the second, which the service provider refuses (section 6.6).');
        }
    }

    /**
     * The time as the writer writes it, in UTC to the second (M-15), as the reader of the service provider reads it
     * back.
     *
     * @throws MalformedMessage when the year is not of four digits
     */
    private function written(DateTimeImmutable $time): DateTimeImmutable
    {
        return Time::read(Time::write($time));
    }

    /**
     * The element of ID $id signed, its Signature after its saml:Issuer.
     *
     * @throws RefusedXml
     * @throws SigningFailed
     */
    private function sign(
        Signer $signer,
        Document $document,
        string $id,
        #[SensitiveParameter]
        Signing $signing,
    ): Document {
        return $signer->sign(
            $document,
            $id,
            $signing->key,
            $signing->algorithm,
            new Name(Saml::ASSERTION, 'Issuer'),
            $signing->certificatePem,
        );
    }
}
