<?php

/**
 * Maho
 *
 * @package    Tests
 * @copyright  Copyright (c) 2026 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

declare(strict_types=1);

use Maho\ApiPlatform\Security\PublicOperationSecurity;

/**
 * Unit tests for the single source of truth on "is this operation public?".
 * API Platform may quote-wrap the security attribute, so the matcher trims
 * quotes/whitespace and recognizes the literal `true`. Anything else —
 * role checks, compound expressions — is intentionally NOT treated as public.
 */
describe('PublicOperationSecurity::isPublic', function (): void {
    it('treats literal-true as public', function (string $security) {
        expect(PublicOperationSecurity::isPublic($security))->toBeTrue();
    })->with([
        'bare true'             => ['true'],
        'single-quoted true'    => ["'true'"],
        'double-quoted true'    => ['"true"'],
        'padded true'           => ['  true  '],
        'uppercase true'        => ['TRUE'],
    ]);

    it('does not treat protected / compound expressions as public', function (?string $security) {
        expect(PublicOperationSecurity::isPublic($security))->toBeFalse();
    })->with([
        'null'                  => [null],
        'false'                 => ['false'],
        'empty'                 => [''],
        'role check'            => ["is_granted('ROLE_ADMIN')"],
        'authenticated'         => ['is_authenticated()'],
        'compound with true'    => ["true or is_granted('ROLE_X')"],
    ]);
});
