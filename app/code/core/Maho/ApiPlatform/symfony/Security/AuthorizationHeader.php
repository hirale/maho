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

final class AuthorizationHeader
{
    private const string AUTHORIZATION_HEADER = 'Authorization';

    /**
     * True only when the Authorization header carries a usable Bearer token —
     * the scheme followed by a non-empty token. A scheme-only `Bearer` (no
     * token) returns false on purpose: callers gate on this to decide whether
     * to engage the authenticator / defer to the firewall, and a malformed
     * tokenless header must not make a public operation 401 before its access
     * control is even consulted. Derived from bearerToken() so the two can
     * never disagree.
     */
    public static function hasBearerScheme(Request $request): bool
    {
        return self::bearerToken($request) !== null;
    }

    public static function bearerToken(Request $request): ?string
    {
        $header = self::authorizationHeader($request);
        if (!preg_match('/^\s*Bearer\s+(.+)$/i', $header, $matches)) {
            return null;
        }

        $token = trim($matches[1]);
        return $token === '' ? null : $token;
    }

    private static function authorizationHeader(Request $request): string
    {
        return (string) $request->headers->get(self::AUTHORIZATION_HEADER, '');
    }
}
