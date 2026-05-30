<?php

/**
 * Maho
 *
 * @package    Maho_ApiPlatform
 * @copyright  Copyright (c) 2026 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */
declare(strict_types=1);

namespace Maho\ApiPlatform\EventListener;

use ApiPlatform\Metadata\Resource\Factory\ResourceMetadataCollectionFactoryInterface;
use Maho\ApiPlatform\Security\PublicOperationSecurity;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

/**
 * Pre-provider authentication enforcement for API Platform operations.
 *
 * With resource-level security (Option #3), the security.yaml catch-all is
 * PUBLIC_ACCESS, so unauthenticated requests reach API Platform. For item
 * operations (Get, Put, Delete), the Provider runs before the security
 * expression is evaluated — which means a missing entity returns 404 before
 * the 401 can fire.
 *
 * This listener runs after the firewall and store authorization listeners
 * (priority 5) and rejects unauthenticated requests to non-public operations
 * before API Platform's read provider has a chance to run.
 */
class DefaultDenyListener
{
    public function __construct(
        private readonly ResourceMetadataCollectionFactoryInterface $resourceMetadataFactory,
        private readonly TokenStorageInterface $tokenStorage,
    ) {}

    public function __invoke(RequestEvent $event): void
    {
        $request = $event->getRequest();

        // Only handle API Platform routes (set by the router)
        $resourceClass = $request->attributes->get('_api_resource_class');
        $operationName = $request->attributes->get('_api_operation_name');
        if ($resourceClass === null || $operationName === null) {
            return;
        }

        // If user is already authenticated (valid token in security context),
        // let API Platform handle authorization normally
        $token = $this->tokenStorage->getToken();
        if ($token !== null && $token->getUser() !== null) {
            return;
        }

        // Look up the operation's security attribute
        try {
            $resourceMetadata = $this->resourceMetadataFactory->create($resourceClass);
            $operation = $resourceMetadata->getOperation($operationName);
            $security = $operation->getSecurity();
        } catch (\Throwable) {
            // If we can't resolve the operation, deny by default
            $security = null;
        }

        // Public operations — no auth needed
        if (PublicOperationSecurity::isPublic($security)) {
            return;
        }

        // No authenticated user and operation requires auth (or has no security attr) -> 401
        $event->setResponse(new JsonResponse([
            'error' => 'unauthorized',
            'message' => 'Authentication required',
        ], 401, ['WWW-Authenticate' => 'Bearer']));
    }
}
