<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\SecurityBundle\Tests\Functional;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\SecurityBundle\Security\WebauthnUtils;

final class SecurityController
{
    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * @var WebauthnUtils
     */
    private $webauthnUtils;

    public function __construct(TokenStorageInterface $tokenStorage, WebauthnUtils $webauthnUtils)
    {
        $this->tokenStorage = $tokenStorage;
        $this->webauthnUtils = $webauthnUtils;
    }

    public function options(Request $request): Response
    {
        $data = new PublicKeyCredentialRequestOptions(
            random_bytes(16),
            60000,
            $request->getHost(),
            [],
            'preferred',
            null
        );
        $request->getSession()->set('__SESSION_PARAMETER__', $data);

        return new JsonResponse($data);
    }

    public function assertion(Request $request): void
    {
    }

    public function logout(): Response
    {
        return new Response('Logout');
    }
}
