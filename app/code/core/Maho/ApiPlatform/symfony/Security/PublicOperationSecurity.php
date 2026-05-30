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

final class PublicOperationSecurity
{
    public static function isPublic(?string $security): bool
    {
        if ($security === null) {
            return false;
        }

        $security = trim(trim($security), "'\"");
        $security = trim($security);

        return strcasecmp($security, 'true') === 0;
    }
}
