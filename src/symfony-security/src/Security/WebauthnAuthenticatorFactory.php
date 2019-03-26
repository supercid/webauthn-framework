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

namespace Webauthn\SecurityBundle\Security;

use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialSourceRepository;

class WebauthnAuthenticatorFactory
{
    /**
     * @var AuthenticatorAssertionResponseValidator
     */
    private $assertionResponseValidator;

    /**
     * @var PublicKeyCredentialLoader
     */
    private $publicKeyCredentialLoader;

    /**
     * @var PublicKeyCredentialSourceRepository
     */
    private $credentialSourceRepository;

    /**
     * @var PublicKeyCredentialUserEntityRepository
     */
    private $userEntityRepository;
    /**
     * @var RequestStack
     */
    private $requestStack;
    /**
     * @var HttpMessageFactoryInterface
     */
    private $psrHttpFactory;

    public function __construct(AuthenticatorAssertionResponseValidator $assertionResponseValidator, PublicKeyCredentialLoader $publicKeyCredentialLoader, PublicKeyCredentialSourceRepository $credentialSourceRepository, PublicKeyCredentialUserEntityRepository $userEntityRepository, RequestStack $requestStack, HttpMessageFactoryInterface $psrHttpFactory)
    {
        $this->assertionResponseValidator = $assertionResponseValidator;
        $this->publicKeyCredentialLoader = $publicKeyCredentialLoader;
        $this->credentialSourceRepository = $credentialSourceRepository;
        $this->userEntityRepository = $userEntityRepository;
        $this->requestStack = $requestStack;
        $this->psrHttpFactory = $psrHttpFactory;
    }

    public function create(string $loginRoute, string $sessionParameterName): WebauthnAuthenticator
    {
        return new WebauthnAuthenticator(
            $loginRoute,
            $sessionParameterName,
            $this->assertionResponseValidator,
            $this->publicKeyCredentialLoader,
            $this->credentialSourceRepository,
            $this->userEntityRepository,
            $this->requestStack,
            $this->psrHttpFactory
        );
    }
}
