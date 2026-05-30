<?php

/**
 * Maho
 *
 * @package    Tests
 * @copyright  Copyright (c) 2026 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

declare(strict_types=1);

use Maho\ApiPlatform\Security\AuthorizationHeader;
use Symfony\Component\HttpFoundation\Request;

/**
 * Unit tests for the Authorization-header parsing helper that the API
 * listeners and the OAuth2 authenticator share. The helper wraps Symfony's
 * HeaderAccessTokenExtractor; these tests pin the contract the call sites
 * rely on: the `Bearer` scheme is matched case-sensitively, a token is
 * required, and whitespace between the scheme and the token is tolerated.
 */
function authRequest(?string $header): Request
{
    $request = Request::create('/api/rest/v2/products');
    if ($header !== null) {
        $request->headers->set('Authorization', $header);
    }
    return $request;
}

describe('AuthorizationHeader::hasBearerScheme', function (): void {
    it('detects a usable Bearer token', function (string $header) {
        expect(AuthorizationHeader::hasBearerScheme(authRequest($header)))->toBeTrue();
    })->with([
        'canonical'        => ['Bearer abc'],
        'tab separator'    => ["Bearer\tabc"],
        'multi-space'      => ['Bearer    abc'],
    ]);

    it('rejects non-Bearer / tokenless / missing / wrong-case schemes', function (?string $header) {
        expect(AuthorizationHeader::hasBearerScheme(authRequest($header)))->toBeFalse();
    })->with([
        'no header'        => [null],
        'empty'           => [''],
        'basic'           => ['Basic dXNlcjpwYXNz'],
        'glued token'      => ['Bearertoken'],
        // Case-sensitive, matching Symfony's HeaderAccessTokenExtractor — a
        // lowercase / mixed-case scheme is NOT recognized.
        'lowercase'        => ['bearer abc'],
        'mixed case'       => ['BeArEr abc'],
        // No leading whitespace tolerated (anchored ^Bearer).
        'leading space'    => ['   Bearer abc'],
        // Scheme-only / tokenless headers must NOT count — otherwise a junk
        // `Authorization: Bearer` 401s public endpoints before access control
        // is consulted (see AuthorizationHeader::hasBearerScheme).
        'scheme only'      => ['Bearer'],
        'scheme + space'   => ['Bearer   '],
    ]);
});

describe('AuthorizationHeader::bearerToken', function (): void {
    it('extracts the token', function () {
        expect(AuthorizationHeader::bearerToken(authRequest('Bearer abc123')))->toBe('abc123');
        expect(AuthorizationHeader::bearerToken(authRequest('Bearer    abc123')))->toBe('abc123');
    });

    it('returns null when there is no usable token', function (?string $header) {
        expect(AuthorizationHeader::bearerToken(authRequest($header)))->toBeNull();
    })->with([
        'no header'        => [null],
        'scheme only'      => ['Bearer'],
        'scheme + space'   => ['Bearer    '],
        'basic'           => ['Basic dXNlcjpwYXNz'],
        'lowercase'        => ['bearer abc123'],
        'leading space'    => ['   Bearer abc123'],
    ]);
});
