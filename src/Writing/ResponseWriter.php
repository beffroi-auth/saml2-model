<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Writing;

use Beffroi\Saml2\Model\Assertion\Assertion;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Writing\ResponseBuilder;
use Beffroi\Saml2\Model\Internal\Writing\Tree;
use Beffroi\Saml2\Model\Protocol\Response;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Dsig\Exception\SigningFailed;
use Beffroi\Xml\Dsig\Signer;
use Beffroi\Xml\Enc\Encryptor;
use Beffroi\Xml\Enc\Exception\EncryptionFailed;
use DateTimeImmutable;
use InvalidArgumentException;
use SensitiveParameter;

/**
 * Sections 6.6 and 6.7
 *
 * The assertion is signed, then encrypted, then the response signed over it: the response's signature covers the
 * ciphertext, and the assertion's travels inside it (SAML Core §6.2).
 */
final readonly class ResponseWriter
{
    /**
     * @throws InvalidArgumentException when the response carries no assertion, or the service provider would
     *                                   refuse the response and its assertion together
     * @throws MalformedMessage when a year is not of four digits
     * @throws RefusedXml
     * @throws SigningFailed
     * @throws EncryptionFailed
     */
    public function write(
        Response $response,
        #[SensitiveParameter]
        Signing $signing,
        SignedParts $parts = SignedParts::Assertion,
        ?Encryption $encryption = null,
    ): Document {
        $assertion =
            $response->assertion ?? throw new InvalidArgumentException('The response carries no assertion: a failure is written by writeFailure() (section 6.6).');
        $this->checkDestination($response);
        $this->check($response, $assertion);
        $signer = new Signer(SamlLoader::create());
        $signed = $this->sign($signer, ResponseBuilder::build($response), $assertion->id, $signing);
        if ($encryption instanceof Encryption) {
            $this->encrypt($signed, $encryption);
        }
        if ($parts === SignedParts::Assertion) {
            return $signed;
        }

        return $this->sign($signer, $signed, $response->id, $signing);
    }

    /**
     * SAML Profiles §4.1.4.1
     *
     * @throws InvalidArgumentException when the response carries an assertion or holds no Destination
     * @throws MalformedMessage when the year of the IssueInstant is not of four digits
     * @throws RefusedXml
     * @throws SigningFailed
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
     * SAML Bindings §3.5.5.2
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
     * Section 6.6 step 1
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
        $issued = $this->written($assertion->issueInstant);
        if ($conditions->notOnOrAfter instanceof DateTimeImmutable && $this->written($conditions->notOnOrAfter) <= $issued) {
            throw new InvalidArgumentException('The NotOnOrAfter of the Conditions is not later than the IssueInstant of the assertion, to the second, which ends it when it is issued (section 6.6).');
        }
        if ($this->written($assertion->confirmation->notOnOrAfter) <= $issued) {
            throw new InvalidArgumentException('The NotOnOrAfter of the bearer confirmation is not later than the IssueInstant of the assertion, to the second, which ends it when it is issued (section 6.6).');
        }
        $sessionNotOnOrAfter = $assertion->authnStatement->sessionNotOnOrAfter;
        if ($sessionNotOnOrAfter instanceof DateTimeImmutable && $this->written($sessionNotOnOrAfter) <= $issued) {
            throw new InvalidArgumentException('The SessionNotOnOrAfter of the authentication statement is not later than the IssueInstant of the assertion, to the second, which ends it when it is issued (section 6.6).');
        }
    }

    /**
     * @throws MalformedMessage when the year is not of four digits
     */
    private function written(DateTimeImmutable $time): DateTimeImmutable
    {
        return Time::read(Time::write($time));
    }

    /**
     * Section 6.7
     *
     * @throws RefusedXml
     * @throws EncryptionFailed
     */
    private function encrypt(Document $document, Encryption $encryption): void
    {
        $response = $document->root();
        $assertion = Children::one($response, new Name(Saml::ASSERTION, 'Assertion'));
        $encrypted = new Encryptor(SamlLoader::create())->encrypt(
            $assertion,
            $encryption->peer,
            $encryption->algorithm,
            $encryption->transport,
        );
        $assertion->remove();
        Tree::of($document)->introduceSaml($response, 'EncryptedAssertion')->appendChild($encrypted);
    }

    /**
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
