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

    public static function hasBearerScheme(Request $request): bool
    {
        return preg_match('/^\s*Bearer(?:\s|$)/i', self::authorizationHeader($request)) === 1;
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
