<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Writing;

use Beffroi\Saml2\Model\Internal\Writing\Tree;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Protocol\NameIdPolicy;
use Beffroi\Saml2\Model\Protocol\RequestedAuthnContext;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Value\Boolean;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Dsig\Exception\SigningFailed;
use Beffroi\Xml\Dsig\Signer;
use Dom\Element;
use InvalidArgumentException;
use SensitiveParameter;

/**
 * A samlp:AuthnRequest written in the order of section 6.6 (section 5.7): checked against what the validator of the
 * identity provider refuses (M-15), the rules of its values already checked by AuthnRequest; built with
 * DocumentFactory and one prefix per namespace, samlp, saml and ds, the saml namespace declared on each element that
 * introduces it; its ID the one the request carries, drawn by SamlId::generate() (M-15), its IssueInstant in UTC to
 * the second, ForceAuthn and IsPassive written only when true; then signed on request through Dsig's Signer with
 * SamlLoader::create(), the Signature after the saml:Issuer (SAML Core §3.2.1, §5.4.1) and no InclusiveNamespaces
 * prefix list (dsig.md section 6.2). Unsigned, it is the document HTTP-Redirect carries, whose binding signs the query
 * string (section 6.8), or an unsigned request over HTTP-POST.
 */
final readonly class AuthnRequestWriter
{
    /**
     * @throws InvalidArgumentException when the request holds no Destination, which the identity provider requires of
     *                                   a request signed by XML or by the binding: a programming error of the caller
     *                                   (section 5.8)
     * @throws RefusedXml what Core's serializer and loader and Dsig refuse while signing
     * @throws SigningFailed when the signing key fails
     */
    public function write(
        AuthnRequest $request,
        #[SensitiveParameter]
        ?Signing $signing,
    ): Document {
        // Section 6.6 step 1: signed by XML or by the binding, which the writer cannot tell apart from an unsigned
        // HTTP-POST, a request without Destination is refused (M-8, SAML Bindings §3.4.5.2, §3.5.5.2)
        if ($request->destination === null) {
            throw new InvalidArgumentException('The request holds no Destination, which the identity provider requires of a signed request, by XML or by the binding (section 6.6).');
        }
        $document = new DocumentFactory()->create(new Name(Saml::PROTOCOL, 'AuthnRequest'), 'samlp');
        $tree = Tree::of($document);
        $root = $document->root();
        $root->setAttribute('ID', $request->id);
        $root->setAttribute('Version', Saml::VERSION);
        $root->setAttribute('IssueInstant', Time::write($request->issueInstant));
        $root->setAttribute('Destination', $request->destination);
        if ($request->forceAuthn) {
            $root->setAttribute('ForceAuthn', Boolean::TRUE);
        }
        if ($request->isPassive) {
            $root->setAttribute('IsPassive', Boolean::TRUE);
        }
        if ($request->protocolBinding !== null) {
            $root->setAttribute('ProtocolBinding', $request->protocolBinding);
        }
        if ($request->assertionConsumerServiceUrl !== null) {
            $root->setAttribute('AssertionConsumerServiceURL', $request->assertionConsumerServiceUrl);
        }
        if ($request->assertionConsumerServiceIndex !== null) {
            $root->setAttribute('AssertionConsumerServiceIndex', (string) $request->assertionConsumerServiceIndex);
        }
        $tree->introduceSaml($root, 'Issuer')->append($request->issuer->entityId);
        if ($request->nameIdPolicy instanceof NameIdPolicy) {
            $this->nameIdPolicy($tree, $root, $request->nameIdPolicy);
        }
        if ($request->requestedAuthnContext instanceof RequestedAuthnContext) {
            $this->requestedAuthnContext($tree, $root, $request->requestedAuthnContext);
        }
        if (! $signing instanceof Signing) {
            return $document;
        }

        return new Signer(SamlLoader::create())->sign(
            $document,
            $request->id,
            $signing->key,
            $signing->algorithm,
            new Name(Saml::ASSERTION, 'Issuer'),
            $signing->certificatePem,
        );
    }

    private function nameIdPolicy(Tree $tree, Element $root, NameIdPolicy $policy): void
    {
        $element = $tree->samlp($root, 'NameIDPolicy');
        if ($policy->format !== null) {
            $element->setAttribute('Format', $policy->format);
        }
        if ($policy->spNameQualifier !== null) {
            $element->setAttribute('SPNameQualifier', $policy->spNameQualifier);
        }
        if ($policy->allowCreate) {
            $element->setAttribute('AllowCreate', Boolean::TRUE);
        }
    }

    private function requestedAuthnContext(Tree $tree, Element $root, RequestedAuthnContext $context): void
    {
        $element = $tree->samlp($root, 'RequestedAuthnContext');
        $element->setAttribute('Comparison', $context->comparison->value);
        foreach ($context->authnContextClassRefs as $authnContextClassRef) {
            $tree->introduceSaml($element, 'AuthnContextClassRef')->append($authnContextClassRef);
        }
    }
}
