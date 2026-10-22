<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Assertion;

use Beffroi\Saml2\Model\Assertion\Assertion;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\MessageRefused;
use Beffroi\Saml2\Model\Internal\Particle;
use Beffroi\Saml2\Model\Internal\Response\SignedAssertion;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\MixedContent;
use function count;
use Dom\Element;

/**
 * The strict reader of an assertion, section 6.1 steps 7 to 11 in order, over the document of a verification (M-1), or
 * of the decryption of a ciphertext a verified signature covered (section 6.7): the
 * root a saml:Assertion, its children in the order and with the cardinality of the schema (M-4, M-5), a ds:Signature
 * after the Issuer accepted and not read (the verification that handed the document over removed the one it verified,
 * D-10), one AuthnStatement, at most one AttributeStatement, any other statement refused by name (section 8); then the
 * header, the subject, the conditions, the authentication statement and the attributes, each by its reader. It takes a
 * Document or the selection of the signed element, never an element: which document covers the assertion is the
 * validator's decision (section 6.1 step 5), and readCovered() is the one entry point the package calls, with the
 * SignedAssertion that selection built from a verification, or from a decryption a verified signature covered, so
 * that no path reads an assertion outside what a signature covered (M-1). The replay of step 13 is the validator's,
 * with the values this returns.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class AssertionReader
{
    /**
     * @throws MessageRefused one of its subclasses, naming the rule (M-16)
     * @throws MixedContent when a value holds an element
     */
    public static function read(Document $document, AssertionContext $context): Assertion
    {
        $assertion = $document->root();
        if (! Schema::saml('Assertion')->matches($assertion)) {
            throw new MalformedMessage('The root of the document is not a saml:Assertion (M-4).');
        }

        return self::assertion($assertion, $context);
    }

    /**
     * The assertion a signature covered (M-1, section 6.1 step 5): the root of the document $covered holds when it is
     * the document of the assertion's own verification, or of the decryption of a ciphertext the response's signature
     * covered (section 6.7), or the one saml:Assertion child of that root when the response's signature covered an
     * unsigned assertion; read as read() reads it, nothing more accepted.
     *
     * @throws MessageRefused one of its subclasses, naming the rule (M-16)
     * @throws MixedContent when a value holds an element
     */
    public static function readCovered(SignedAssertion $covered, AssertionContext $context): Assertion
    {
        $root = $covered->document->root();
        if (Schema::saml('Assertion')->matches($root)) {
            return self::assertion($root, $context);
        }
        if (! Schema::samlp('Response')->matches($root)) {
            throw new MalformedMessage('The root of the verified document is neither a saml:Assertion nor a samlp:Response (M-1).');
        }
        $assertions = Children::named($root, Schema::saml('Assertion'));
        if (count($assertions) !== 1) {
            throw new MalformedMessage('The verified samlp:Response does not hold exactly one saml:Assertion (M-4).');
        }

        return self::assertion($assertions[0], $context);
    }

    /**
     * @throws MessageRefused
     * @throws MixedContent
     */
    private static function assertion(Element $assertion, AssertionContext $context): Assertion
    {
        Schema::unsupported(
            $assertion,
            [Schema::saml('Statement'), Schema::saml('AuthzDecisionStatement')],
            'The assertion holds a statement other than AuthnStatement and AttributeStatement, which the package does not support (section 8).',
        );
        Schema::children($assertion, 'saml:Assertion', [
            Particle::of(Schema::saml('Issuer'), 1, 1),
            Particle::of(Schema::ds('Signature'), 0, 1),
            Particle::of(Schema::saml('Subject'), 1, 1),
            Particle::of(Schema::saml('Conditions'), 1, 1),
            Particle::of(Schema::saml('Advice'), 0, 1),
            new Particle(
                'statement',
                [Schema::saml('AuthnStatement'), Schema::saml('AttributeStatement')],
                0,
                Particle::UNBOUNDED,
            ),
        ]);
        $authnStatements = Children::named($assertion, Schema::saml('AuthnStatement'));
        if ($authnStatements === []) {
            throw new MalformedMessage('The saml:Assertion holds no saml:AuthnStatement (M-4).');
        }
        if (count($authnStatements) > 1) {
            throw new MalformedMessage('The saml:Assertion holds more than one saml:AuthnStatement (M-4).');
        }
        $attributeStatements = Children::named($assertion, Schema::saml('AttributeStatement'));
        if (count($attributeStatements) > 1) {
            throw new MalformedMessage('The saml:Assertion holds more than one saml:AttributeStatement (M-4).');
        }
        [$id, $issueInstant, $issuer] = HeaderReader::read($assertion, $context);
        [$nameId, $confirmation] = SubjectReader::read(Children::one($assertion, Schema::saml('Subject')), $context);

        return new Assertion(
            $id,
            $issueInstant,
            $issuer,
            $nameId,
            $confirmation,
            ConditionsReader::read(Children::one($assertion, Schema::saml('Conditions')), $context),
            AuthnStatementReader::read($authnStatements[0], $context),
            $attributeStatements === [] ? [] : AttributeStatementReader::read($attributeStatements[0]),
        );
    }
}
