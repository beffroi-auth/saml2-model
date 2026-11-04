<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Writing;

use Beffroi\Saml2\Model\Internal\Writing\StatusBuilder;
use Beffroi\Saml2\Model\Internal\Writing\Tree;
use Beffroi\Saml2\Model\Protocol\LogoutResponse;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Dsig\Exception\SigningFailed;
use Beffroi\Xml\Dsig\Signer;
use SensitiveParameter;

/**
 * Section 6.6, SAML Core §3.2.1
 */
final readonly class LogoutResponseWriter
{
    private const string XMLNS = 'http://www.w3.org/2000/xmlns/';

    /**
     * @throws RefusedXml
     * @throws SigningFailed
     */
    public function write(
        LogoutResponse $response,
        #[SensitiveParameter]
        ?Signing $signing,
    ): Document {
        $document = new DocumentFactory()->create(new Name(Saml::PROTOCOL, 'LogoutResponse'), 'samlp');
        $tree = Tree::of($document);
        $root = $document->root();
        $root->setAttributeNS(self::XMLNS, 'xmlns:saml', Saml::ASSERTION);
        $root->setAttribute('ID', $response->id);
        $root->setAttribute('Version', Saml::VERSION);
        $root->setAttribute('IssueInstant', Time::write($response->issueInstant));
        $root->setAttribute('Destination', $response->destination);
        $root->setAttribute('InResponseTo', $response->inResponseTo);
        $tree->saml($root, 'Issuer')->append($response->issuer->entityId);
        StatusBuilder::append($tree, $root, $response->status);
        if (! $signing instanceof Signing) {
            return $document;
        }

        return new Signer(SamlLoader::create())->sign(
            $document,
            $response->id,
            $signing->key,
            $signing->algorithm,
            after: new Name(Saml::ASSERTION, 'Issuer'),
            certificatePem: $signing->certificatePem,
        );
    }
}
