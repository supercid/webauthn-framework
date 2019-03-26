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

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockFileSessionStorage;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * @group functional
 */
class SecuredAreaTest extends WebTestCase
{
    /**
     * @test
     */
    public function aClientIsRedirectedIfUserIsNotAuthenticated(): void
    {
        $client = static::createClient();
        $client->request('GET', '/admin', [], [], ['HTTPS' => 'on']);

        static::assertEquals(302, $client->getResponse()->getStatusCode());
        static::assertTrue($client->getResponse()->headers->has('location'));
        static::assertEquals('https://localhost/login', $client->getResponse()->headers->get('location'));
    }

    /**
     * @test
     */
    public function aUserCanAskForPublicKeyCredentialRequestOptions(): void
    {
        $client = static::createClient();
        $client->request('POST', '/login/options', [], [], ['HTTPS' => 'on']);

        static::assertEquals(200, $client->getResponse()->getStatusCode());
    }

    /**
     * @test
     */
    public function aUserCanSendAnAssertionRequest(): void
    {
        $session = new Session(new MockFileSessionStorage());
        $session->set('__SESSION_PARAMETER__', PublicKeyCredentialRequestOptions::createFromJson(\Safe\json_decode('{"challenge":"G0JbLLndef3a0Iy3S2sSQA8uO4SO\/ze6FZMAuPI6+xI=","rpId":"localhost","userVerification":"preferred","allowCredentials":[{"type":"public-key","id":"eHouz\/Zi7+BmByHjJ\/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp\/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w=="}],"timeout":60000}', true)));
        $session->save();

        $client = static::createClient();
        $client->getContainer()->set('session', $session);

        $content = '{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MBAAAAew==","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ==","signature":"MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=","userHandle":null}}';

        $client->request('POST', '/login/assertion', [], [], ['HTTPS' => 'on', 'CONTENT_TYPE' => 'application/json'], $content);

        static::assertEquals(200, $client->getResponse()->getStatusCode());
        static::assertEquals('{"status":"ok"}', $client->getResponse()->getContent());
        static::assertEquals('application/json', $client->getResponse()->headers->get('content-type'));
    }
}
