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

use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Security\Authentication\Provider\MetaWebauthnProvider;
use Webauthn\Bundle\Security\EntryPoint\WebauthnEntryPoint;
use Webauthn\Bundle\Security\Firewall\WebauthnListener;
use Webauthn\Bundle\Security\WebauthnUtils;
use Webauthn\PublicKeyCredentialLoader;
use function Symfony\Component\DependencyInjection\Loader\Configurator\ref;

return function (ContainerConfigurator $container) {
    $container->services()->set(MetaWebauthnProvider::class)
        ->abstract(true)
        ->private()
        ->arg(0, ref(UserCheckerInterface::class))
    ;

    $container->services()->set('security.authentication.listener.webauthn')
        ->class(WebauthnListener::class)
        ->abstract(true)
        ->private()
        ->args([
            ref(PublicKeyCredentialLoader::class),
            ref(AuthenticatorAssertionResponseValidator::class),
            ref(TokenStorageInterface::class),
            ref(AuthenticationManagerInterface::class),
            ref(SessionAuthenticationStrategyInterface::class),
            ref(HttpUtils::class),
            '',
            [],
            ref(LoggerInterface::class)->nullOnInvalid(),
            ref(EventDispatcherInterface::class)->nullOnInvalid(),
            ref(CsrfTokenManagerInterface::class)->nullOnInvalid(),
        ])
        ->tag('monolog.logger', ['channel' => 'security'])
    ;

    $container->services()->set(WebauthnEntryPoint::class)
        ->abstract(true)
        ->private()
        ->arg(0, ref(KernelInterface::class))
    ;

    $container->services()->set(WebauthnUtils::class)
        ->private()
        ->args([
            ref(\Symfony\Component\HttpFoundation\RequestStack::class),
        ]);
};