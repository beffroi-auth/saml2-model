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
 * Section 6.6, SAML Core §3.2.1
 */
final readonly class LogoutRequestWriter
{
    private const string XMLNS = 'http://www.w3.org/2000/xmlns/';

    /**
     * @throws InvalidArgumentException when the NotOnOrAfter is not later than the IssueInstant, both to the second
     * @throws RefusedXml
     * @throws SigningFailed
     */
    public function write(
        LogoutRequest $request,
        #[SensitiveParameter]
        ?Signing $signing,
    ): Document {
        if ($request->notOnOrAfter instanceof DateTimeImmutable && $this->written($request->notOnOrAfter) <= $this->written($request->issueInstant)) {
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
     * @throws MalformedMessage when the year is not of four digits
     */
    private function written(DateTimeImmutable $time): DateTimeImmutable
    {
        return Time::read(Time::write($time));
    }
}
