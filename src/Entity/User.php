<?php

declare(strict_types=1);

namespace Atoolo\Security\Entity;

use Atoolo\Security\SiteKit\RoleMapper;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

final class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    /**
     * @var string
     */
    private $username;

    /**
     * @var string
     */
    private $password;

    /**
     * @var array<string>
     */
    private $roles;

    /**
     * @param array<string> $roles
     */
    public function __construct(string $username, array $roles)
    {
        $this->username = $username;
        $this->roles    = $roles;
    }

    /**
     * @param array{username?: string, password?: string, roles?: array<string>} $data
     * @return User
     */
    public static function ofArray(array $data): User
    {

        if (!isset($data['username'], $data['password'], $data['roles'])) {
            throw new \SP\Sitepark\RoutingBundle\Exception\RuntimeException(
                'Invalid User data provided. Expected array with keys username, password and roles'
            );
        }

        $roles = RoleMapper::map($data['roles']);
        $user  = new User($data['username'], $roles);
        $user->setPassword($data['password']);

        return $user;
    }

    /**
     * @return array<string>
     */
    public function getRoles(): array
    {
        return $this->roles;
    }

    public function setPassword(string $password): void
    {
        $this->password = $password;
    }

    public function getPassword(): ?string
    {
        return $this->password;
    }

    public function getSalt(): ?string
    {
        return null;
    }

    public function eraseCredentials(): void
    {
    }

    /**
     * The public representation of the user (e.g. a username, an email address, etc.)
     *
     * @see UserInterface
     */
    public function getUserIdentifier(): string
    {
        return $this->username;
    }

    /**
     * @deprecated since Symfony 5.3
     */
    public function getUsername(): string
    {
        return $this->username;
    }
}
