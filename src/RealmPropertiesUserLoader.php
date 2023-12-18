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
        foreach (preg_split("/((\r?\n)|(\r\n?))/", $content) as $line) {
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
        $plaintextPassword = substr($value, 0, $separator);
        $plaintextPassword = trim($plaintextPassword);
        $roles = $this->parseRoles(substr($value, $separator + 1));
        $user = new User($name, $roles);
        $hashedPassword = $this->passwordHasher->hashPassword(
            $user,
            $plaintextPassword
        );
        $user->setPassword($hashedPassword);
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
