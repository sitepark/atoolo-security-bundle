<?php

declare(strict_types=1);

namespace Atoolo\Security;

use Atoolo\Security\Entity\User;
use Atoolo\Security\SiteKit\RoleMapper;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class RealmPropertiesUserLoader implements UserLoader
{
    /**
     * @var UserPasswordHasherInterface
     */
    private $passwordHasher;

    /**
     * @var string
     */
    private $realmPropertiesFile;

    public function __construct(
        string $realmPropertiesFile,
        UserPasswordHasherInterface $passwordHasher
    ) {
        $this->realmPropertiesFile = $realmPropertiesFile;
        $this->passwordHasher      = $passwordHasher;
    }

    /**
     * @return array<string,UserInterface>
     */
    public function load(): array
    {
        $userList = [];
        $realm = $this->loadRealm();
        foreach ($realm as $name => $value) {
            $user = $this->createUser($name, $value);
            $userList[$user->getUserIdentifier()] = $user;
        }

        return $userList;
    }

    /**
     * @return array<string,string>
     */
    private function loadRealm(): array
    {
        $realm = [];
        $content = file_get_contents($this->realmPropertiesFile);
        if (!is_string($content)) {
            return $realm;
        }

        $lines = preg_split("/((\r?\n)|(\r\n?))/", $content);
        if (!is_array($lines)) {
            return $realm;
        }

        foreach ($lines as $line) {
            if (str_starts_with($line, ';') || str_starts_with($line, '#')) {
                continue;
            }
            $parts = explode(':', $line);
            if (count($parts) !== 2) {
                continue;
            }
            $user = $parts[0];
            $realm[$user] = trim($parts[1]);
        }

        return $realm;
    }

    private function createUser(string $name, string $value): User
    {
        $separator = strpos($value, ',');
        if (is_int($separator)) {
            $plaintextPassword = substr($value, 0, $separator);
        } else {
            $plaintextPassword = '';
        }
        $plaintextPassword = trim($plaintextPassword);
        $roles = $this->parseRoles(substr($value, $separator + 1));
        $user = new User($name, $roles);

        /**
         * The password is provided here via a callback, as the realm.properties
         * contains the password in plain text. However, the User:setPassword()
         * expects a hashed password. hashing the password is very
         * time-consuming. The callback ensures that the password is only hashed
         * if it is necessary. It is only necessary for an authentication
         * process.It is not necessary when creating a user object via a JWT.
         * This optimization is precisely for this case.
         */
        $user->setPasswordCallback(function () use ($plaintextPassword, $user) {
            return $this->passwordHasher->hashPassword(
                $user,
                $plaintextPassword
            );
        });

        return $user;
    }

    /**
     * @return array<string>
     */
    private function parseRoles(string $value): array
    {
        $roles = explode(',', $value);
        return RoleMapper::map($roles);
    }
}
