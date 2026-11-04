<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\AuthnRequest;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\UnknownEndpoint;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Value\UnsignedShort;
use Beffroi\Saml2\Model\Value\Uri;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Name;
use Dom\Element;

/**
 * Section 6.2 step 4, M-9
 *
 * @internal
 */
final readonly class AssertionConsumerService
{
    /**
     * @return array{IndexedEndpoint, ?string, ?int, ?string} the endpoint, the URL, the index and the binding
     *
     * @throws MalformedMessage
     * @throws UnknownEndpoint
     * @throws Unsupported
     */
    public static function read(Element $request, IndexedEndpoints $services): array
    {
        $url = Attributes::optional($request, new Name(null, 'AssertionConsumerServiceURL'));
        $url = $url === null ? null : Uri::read($url);
        $index = Attributes::optional($request, new Name(null, 'AssertionConsumerServiceIndex'));
        $index = $index === null ? null : UnsignedShort::read($index);
        $binding = Attributes::optional($request, new Name(null, 'ProtocolBinding'));
        $binding = $binding === null ? null : Uri::read($binding);
        self::exclusive($url, $index, $binding);
        $endpoint = match (true) {
            $url !== null => $services->byLocation($url),
            $index !== null => $services->byIndex($index),
            default => $services->default(),
        };

        return [$endpoint, $url, $index, $binding === null ? null : self::protocolBinding($binding)];
    }

    /**
     * SAML Core §3.4.1
     *
     * @throws MalformedMessage
     */
    public static function exclusive(?string $url, ?int $index, ?string $protocolBinding): void
    {
        if ($index !== null && ($url !== null || $protocolBinding !== null)) {
            throw new MalformedMessage('An AuthnRequest carries an AssertionConsumerServiceIndex next to an AssertionConsumerServiceURL or a ProtocolBinding, which SAML Core §3.4.1 makes mutually exclusive (M-9).');
        }
    }

    /**
     * Section 8
     *
     * @throws Unsupported
     */
    public static function protocolBinding(string $uri): string
    {
        if ($uri !== Binding::HttpPost->value) {
            throw new Unsupported('The ProtocolBinding of an AuthnRequest is not HTTP-POST, the one binding the package answers over (section 8).');
        }

        return $uri;
    }
}
