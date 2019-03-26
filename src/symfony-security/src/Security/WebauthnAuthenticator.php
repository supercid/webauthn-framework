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

use Assert\Assertion;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Symfony\Component\Security\Guard\Token\GuardTokenInterface;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

class WebauthnAuthenticator extends AbstractGuardAuthenticator
{
    private const ERROR_INVALID_ASSERTION = 597;
    private const ERROR_NO_SESSION = 598;
    private const ERROR_PK_REQUEST_OPTIONS = 599;

    /**
     * @var string
     */
    private $loginRoute;

    /**
     * @var string
     */
    private $sessionParameterName;

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
     * @var AuthenticatorAssertionResponseValidator
     */
    private $assertionResponseValidator;

    /**
     * @var HttpMessageFactoryInterface
     */
    private $psrHttpFactory;

    /**
     * @var RequestStack
     */
    private $requestStack;

    public function __construct(string $loginRoute, string $sessionParameterName, AuthenticatorAssertionResponseValidator $assertionResponseValidator, PublicKeyCredentialLoader $publicKeyCredentialLoader, PublicKeyCredentialSourceRepository $credentialSourceRepository, PublicKeyCredentialUserEntityRepository $userEntityRepository, RequestStack $requestStack, HttpMessageFactoryInterface $psrHttpFactory)
    {
        $this->loginRoute = $loginRoute;
        $this->sessionParameterName = $sessionParameterName;
        $this->publicKeyCredentialLoader = $publicKeyCredentialLoader;
        $this->credentialSourceRepository = $credentialSourceRepository;
        $this->userEntityRepository = $userEntityRepository;
        $this->assertionResponseValidator = $assertionResponseValidator;
        $this->requestStack = $requestStack;
        $this->psrHttpFactory = $psrHttpFactory;
    }

    public function supports(Request $request): bool
    {
        return $request->isMethod(Request::METHOD_POST) && $this->loginRoute === $request->attributes->get('_route') && 'json' === $request->getContentType();
    }

    /**
     * Called on every request. Return whatever credentials you want to
     * be passed to getUser() as $credentials.
     */
    public function getCredentials(Request $request): ?array
    {
        $session = $request->getSession();
        if (null === $session) {
            throw new AuthenticationException('No session available', self::ERROR_NO_SESSION);
        }
        $publicKeyCredentialRequestOptions = $session->remove($this->sessionParameterName);
        if (!$publicKeyCredentialRequestOptions instanceof PublicKeyCredentialRequestOptions) {
            throw new AuthenticationException('No public key credential request options available', self::ERROR_PK_REQUEST_OPTIONS);
        }
        $content = $request->getContent();

        try {
            Assertion::notEmpty($content, 'No assertion', self::ERROR_INVALID_ASSERTION);
            $publicKeyCredential = $this->publicKeyCredentialLoader->load($content);
        } catch (\Throwable $throwable) {
            throw new AuthenticationException('Invalid assertion', self::ERROR_INVALID_ASSERTION, $throwable);
        }

        $credentialSource = $this->credentialSourceRepository->findOneByCredentialId($publicKeyCredential->getRawId());
        if (null === $credentialSource) {
            throw new AuthenticationException('Invalid assertion', self::ERROR_INVALID_ASSERTION);
        }
        $userEntity = $this->userEntityRepository->findOneByUserHandle($credentialSource->getUserHandle());
        if (null === $userEntity) {
            throw new AuthenticationException('Invalid assertion', self::ERROR_INVALID_ASSERTION);
        }

        return [
            'options' => $publicKeyCredentialRequestOptions,
            'credential' => $publicKeyCredential,
            'userEntity' => $userEntity,
            'credentialSource' => $credentialSource,
        ];
    }

    public function getUser($credentials, UserProviderInterface $userProvider): ?UserInterface
    {
        try {
            Assertion::keyExists($credentials, 'userEntity');
            $userEntity = $credentials['userEntity'];
            Assertion::isInstanceOf($userEntity, PublicKeyCredentialUserEntity::class);
        } catch (\Throwable $throwable) {
            return null;
        }

        return $userProvider->loadUserByUsername($userEntity->getName());
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        try {
            Assertion::keyExists($credentials, 'options', 'Invalid credentials');
            Assertion::keyExists($credentials, 'credential', 'Invalid credentials');
            Assertion::keyExists($credentials, 'userEntity', 'Invalid credentials');
            $publicKeyCredentialRequestOptions = $credentials['options'];
            $publicKeyCredential = $credentials['credential'];
            $userEntity = $credentials['userEntity'];
            Assertion::isInstanceOf($publicKeyCredentialRequestOptions, PublicKeyCredentialRequestOptions::class, 'iInvalid credentials');
            Assertion::isInstanceOf($publicKeyCredential, PublicKeyCredential::class, 'Invalid credentials');
            Assertion::isInstanceOf($userEntity, PublicKeyCredentialUserEntity::class, 'Invalid credentials');
            $response = $publicKeyCredential->getResponse();
            Assertion::isInstanceOf($response, AuthenticatorAssertionResponse::class, 'Invalid response');
            $request = $this->requestStack->getCurrentRequest();
            Assertion::isInstanceOf($request, Request::class, 'Invalid request');
            $psr7Request = $this->psrHttpFactory->createRequest($request);

            $this->assertionResponseValidator->check(
                $publicKeyCredential->getRawId(),
                $response,
                $publicKeyCredentialRequestOptions,
                $psr7Request,
                $userEntity->getId()
            );
        } catch (\Throwable $throwable) {
            throw new AuthenticationException('Invalid credentials', self::ERROR_INVALID_ASSERTION, $throwable);
        }

        return true;
    }

    public function createAuthenticatedToken(UserInterface $user, $providerKey): GuardTokenInterface
    {
        return parent::createAuthenticatedToken($user, $providerKey);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey): Response
    {
        dump($token);
        return new JsonResponse(['status' => 'ok'], Response::HTTP_OK);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        $data = [
            'message' => strtr($exception->getMessageKey(), $exception->getMessageData()),
        ];

        return new JsonResponse($data, Response::HTTP_FORBIDDEN);
    }

    /**
     * Called when authentication is needed, but it's not sent.
     */
    public function start(Request $request, AuthenticationException $authException = null): Response
    {
        $data = [
            'message' => 'Authentication Required',
        ];

        return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
    }

    public function supportsRememberMe(): bool
    {
        return true;
    }
}
