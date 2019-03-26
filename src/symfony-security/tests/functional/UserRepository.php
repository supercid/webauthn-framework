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

use Webauthn\Bundle\Repository\PublicKeyCredentialUserEntityRepository;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialUserEntity;

final class UserRepository implements PublicKeyCredentialUserEntityRepository
{
    /**
     * @var User[]
     */
    private $users;

    public function __construct()
    {
        $this->users = [
            'admin' => new User('foo', 'admin', ['ROLE_ADMIN', 'ROLE_USER'], [new PublicKeyCredentialDescriptor(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                \Safe\base64_decode('eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==', true)
            )]),
        ];
    }

    public function findOneByUsername(string $username): ?PublicKeyCredentialUserEntity
    {
        if ('admin' === $username) {
            return new PublicKeyCredentialUserEntity('admin', 'foo', 'Administrator');
        }

        return null;
    }

    public function findByUsername(string $username): ?User
    {
        if (\array_key_exists($username, $this->users)) {
            return $this->users[$username];
        }

        return null;
    }

    public function findOneByUserHandle(string $userHandle): ?PublicKeyCredentialUserEntity
    {
        if ('foo' === $userHandle) {
            return new PublicKeyCredentialUserEntity('admin', 'foo', 'Administrator');
        }

        return null;
    }

    public function createUserEntity(string $username, string $displayName, ?string $icon): PublicKeyCredentialUserEntity
    {
    }

    public function saveUserEntity(PublicKeyCredentialUserEntity $userEntity): void
    {
    }
}
