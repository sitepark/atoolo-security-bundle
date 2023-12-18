<?php

declare(strict_types=1);

namespace Atoolo\Security\SiteKit;

use Psr\Log\LoggerInterface;
use Atoolo\Security\Entity\User as UserEntity;
use Atoolo\Security\UserLoader as UserLoaderInterface;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Security\Core\User\UserInterface;

class UserLoader implements UserLoaderInterface
{
    /**
     * @var LoggerInterface
     */
    private $logger;

    public function __construct(LoggerInterface $logger)
    {
        $this->logger  = $logger;
    }

    /**
     * @return array<string,UserInterface>
     */
    public function load(): array
    {

        $userList = [];

        $baseDir = $_SERVER['RESOURCE_ROOT'] . '/security';

        if (!is_dir($baseDir)) {
            return $userList;
        }

        $finder = new Finder();
        $finder->in($baseDir);

        $userList = [[]];
        foreach ($finder->files()->name('*.users.php') as $file) {
            $userList[] = $this->createUserListByFile($file->getRealPath());
        }
        return array_merge(...$userList);
    }

    /**
     * @return array<string,UserInterface>
     */
    private function createUserListByFile(string $file): array
    {
        $userList = [];
        try {
            $dataList = $this->loadDataList($file);
            foreach ($dataList as $data) {
                $user = UserEntity::ofArray($data);
                $userList[$user->getUserIdentifier()] = $user;
            }
        } catch (\Throwable $t) {
            $this->logger->error(
                'unable to load user',
                ['file' => $file, 'exception' => $t]
            );
        }
        return $userList;
    }

    /**
     * @return array<array{username: string, password: string, roles: array<string>}>
     */
    private function loadDataList(string $file): array
    {
		// phpcs:ignore
		return @include $file;
    }
}
