<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\AuthnRequest;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\UnknownEndpoint;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Value\Uri;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Name;
use Dom\Element;
use function preg_match;

/**
 * The assertion consumer service of an AuthnRequest, section 6.2 step 4 (M-9): resolved in the service provider's
 * metadata and nowhere else, by the AssertionConsumerServiceURL, by the AssertionConsumerServiceIndex, or else the
 * default of SAML Metadata §2.2.3, over the HTTP-POST services the metadata reader kept (section 6.5 step 6); the
 * index mutually exclusive with the URL and with the ProtocolBinding (SAML Core §3.4.1); the ProtocolBinding HTTP-POST.
 * The AuthnRequest value applies the last two rules too, whoever builds it (M-15), through the same two methods.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class AssertionConsumerService
{
    private const int MAX_INDEX = 65_535;

    /**
     * The endpoint the response goes to, and the three attributes of the request that name it, as read.
     *
     * @return array{IndexedEndpoint, ?string, ?int, ?string} the endpoint, the URL, the index and the binding
     *
     * @throws MalformedMessage when an attribute is not of its lexical form (M-6), or the index is next to the URL or
     *                          the ProtocolBinding (M-9)
     * @throws UnknownEndpoint when the metadata lists no service of that URL or index (M-9)
     * @throws Unsupported when the ProtocolBinding is not HTTP-POST (section 8)
     */
    public static function read(Element $request, IndexedEndpoints $services): array
    {
        $url = Attributes::optional($request, new Name(null, 'AssertionConsumerServiceURL'));
        $url = $url === null ? null : Uri::read($url);
        $index = Attributes::optional($request, new Name(null, 'AssertionConsumerServiceIndex'));
        $index = $index === null ? null : self::index($index);
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
     * SAML Core §3.4.1: the AssertionConsumerServiceIndex is mutually exclusive with the AssertionConsumerServiceURL
     * and with the ProtocolBinding.
     *
     * @throws MalformedMessage when the index is next to either (M-9)
     */
    public static function exclusive(?string $url, ?int $index, ?string $protocolBinding): void
    {
        if ($index !== null && ($url !== null || $protocolBinding !== null)) {
            throw new MalformedMessage('An AuthnRequest carries an AssertionConsumerServiceIndex next to an AssertionConsumerServiceURL or a ProtocolBinding, which SAML Core §3.4.1 makes mutually exclusive (M-9).');
        }
    }

    /**
     * The one place of the rule of section 8 on the ProtocolBinding of a request: HTTP-POST, the binding the response
     * is sent over; HTTP-Redirect cannot carry a response and the Artifact binding is out of scope.
     *
     * @return string the URI, HTTP-POST's
     *
     * @throws Unsupported for every other binding (section 8)
     */
    public static function protocolBinding(string $uri): string
    {
        if ($uri !== Binding::HttpPost->value) {
            throw new Unsupported('The ProtocolBinding of an AuthnRequest is not HTTP-POST, the one binding the package answers over (section 8).');
        }

        return $uri;
    }

    /**
     * An xs:unsignedShort in its one lexical form (M-6): decimal digits without sign, whitespace or leading zero, at
     * most 65535.
     *
     * @throws MalformedMessage
     */
    private static function index(string $index): int
    {
        if (preg_match('~^(?:0|[1-9]\d{0,4})\z~', $index) !== 1 || (int) $index > self::MAX_INDEX) {
            throw new MalformedMessage('The AssertionConsumerServiceIndex of an AuthnRequest is not an xs:unsignedShort without sign or leading zero (M-6).');
        }

        return (int) $index;
    }
}
