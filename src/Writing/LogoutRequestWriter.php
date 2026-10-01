<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Writing;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\Writing\NameIdBuilder;
use Beffroi\Saml2\Model\Internal\Writing\Tree;
use Beffroi\Saml2\Model\Protocol\LogoutRequest;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Dsig\Exception\SigningFailed;
use Beffroi\Xml\Dsig\Signer;
use DateTimeImmutable;
use InvalidArgumentException;
use SensitiveParameter;

/**
 * A samlp:LogoutRequest written in the order of section 6.6 (section 5.7): what its reader would refuse, its
 * constructor refused already, but a NotOnOrAfter not later than the IssueInstant, which the writer refuses (M-15); built with DocumentFactory and one prefix per namespace, samlp and saml, both
 * declared on the root, the ID the request carries, the times in UTC to the second, the Format of the NameID always
 * written; then signed on request through Dsig's Signer with SamlLoader::create(), the Signature after the Issuer
 * (SAML Core §3.2.1) and no InclusiveNamespaces prefix list. Signed for HTTP-POST, unsigned for HTTP-Redirect, whose
 * binding signs the query string (section 6.8).
 */
final readonly class LogoutRequestWriter
{
    private const string XMLNS = 'http://www.w3.org/2000/xmlns/';

    /**
     * @throws InvalidArgumentException when the NotOnOrAfter is not later than the IssueInstant, the two compared as
     *                                   they are written, to the second, which the reader refuses (section 6.6): a
     *                                   programming error of the caller (section 5.8)
     * @throws RefusedXml what Core's serializer and loader and Dsig refuse while signing
     * @throws SigningFailed when the signing key fails
     */
    public function write(
        LogoutRequest $request,
        #[SensitiveParameter]
        ?Signing $signing,
    ): Document {
        if (
            $request->notOnOrAfter instanceof DateTimeImmutable
            && $this->written($request->notOnOrAfter) <= $this->written($request->issueInstant)
        ) {
            throw new InvalidArgumentException('The NotOnOrAfter of the LogoutRequest is not later than its IssueInstant, to the second, which its reader refuses (section 6.6).');
        }
        $document = new DocumentFactory()->create(new Name(Saml::PROTOCOL, 'LogoutRequest'), 'samlp');
        $tree = Tree::of($document);
        $root = $document->root();
        $root->setAttributeNS(self::XMLNS, 'xmlns:saml', Saml::ASSERTION);
        $root->setAttribute('ID', $request->id);
        $root->setAttribute('Version', Saml::VERSION);
        $root->setAttribute('IssueInstant', Time::write($request->issueInstant));
        $root->setAttribute('Destination', $request->destination);
        if ($request->notOnOrAfter instanceof DateTimeImmutable) {
            $root->setAttribute('NotOnOrAfter', Time::write($request->notOnOrAfter));
        }
        if ($request->reason !== null) {
            $root->setAttribute('Reason', $request->reason);
        }
        $tree->saml($root, 'Issuer')->append($request->issuer->entityId);
        NameIdBuilder::append($tree, $root, $request->nameId);
        foreach ($request->sessionIndexes as $sessionIndex) {
            $tree->samlp($root, 'SessionIndex')->append($sessionIndex);
        }
        if (! $signing instanceof Signing) {
            return $document;
        }

        return new Signer(SamlLoader::create())->sign(
            $document,
            $request->id,
            $signing->key,
            $signing->algorithm,
            after: new Name(Saml::ASSERTION, 'Issuer'),
            certificatePem: $signing->certificatePem,
        );
    }

    /**
     * The time as the writer writes it, in UTC to the second (M-15), as its reader reads it back.
     *
     * @throws MalformedMessage when the year is not of four digits
     */
    private function written(DateTimeImmutable $time): DateTimeImmutable
    {
        return Time::read(Time::write($time));
    }
}
