<?php

declare(strict_types=1);

/**
 * Maho
 *
 * @package    Maho_ApiPlatform
 * @copyright  Copyright (c) 2026 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

namespace Maho\ApiPlatform\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\AccessToken\HeaderAccessTokenExtractor;

/**
 * Single source of truth for reading a Bearer token off the Authorization
 * header, shared by the OAuth2 authenticator and the pre-firewall API
 * listeners so they all parse it identically.
 *
 * Parsing is delegated to Symfony's HeaderAccessTokenExtractor — the same
 * extractor the framework's own access_token authenticator uses — so the
 * `Bearer` scheme is matched case-sensitively, a token is required, and the
 * token must match the RFC 6750 grammar.
 */
final class AuthorizationHeader
{
    /**
     * True only when the Authorization header carries a usable Bearer token —
     * a scheme-only `Bearer` (no token) returns false on purpose. Callers gate
     * on this to decide whether to engage the authenticator / defer to the
     * firewall, and a malformed tokenless header must not make a public
     * operation 401 before its access control is even consulted. Derived from
     * bearerToken() so the two can never disagree.
     */
    public static function hasBearerScheme(Request $request): bool
    {
        return self::bearerToken($request) !== null;
    }

    public static function bearerToken(Request $request): ?string
    {
        return (new HeaderAccessTokenExtractor())->extractAccessToken($request);
    }
}
