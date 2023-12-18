<?php

declare(strict_types=1);

namespace Atoolo\Security\Test\SiteKit;

use Atoolo\Security\SiteKit\UserLoader;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

/**
 * @covers \Atoolo\Security\SiteKit\UserLoader
 */
class UserLoaderTest extends TestCase
{
    /**
     * @var array<string,string>
     */
    private array $saveServerState;

    public function setUp(): void
    {
        $this->saveServerState = $_SERVER;
    }

    public function tearDown(): void
    {
        $_SERVER = $this->saveServerState;
    }

    /*+
     * @covers UserLoader
     */
    public function testDirNotExists(): void
    {

        $mockLogger = $this->createMock(LoggerInterface::class);
        $_SERVER['RESOURCE_ROOT'] = __DIR__ . '/security-not-exists';

        $loader = new UserLoader($mockLogger);
        $users = $loader->load();

        $this->assertIsArray($users);
        $this->assertEmpty($users);
    }

    /*+
     * @covers UserLoader
     */
    public function testLoadDir(): void
    {

        $mockLogger = $this->createMock(LoggerInterface::class);
        $mockLogger->expects($this->once())
            ->method('error');

        $_SERVER['RESOURCE_ROOT'] = __DIR__;
        $loader = new UserLoader($mockLogger);
        $users = $loader->load();

        $this->assertIsArray($users);
        $this->assertCount(3, $users);

        $this->assertEquals('a', $users['a']->getUserIdentifier());
        $this->assertEquals("hash:a", $users['a']->getPassword());
        $this->assertEquals(['ROLE_USER'], $users['a']->getRoles());

        $this->assertEquals('b', $users['b']->getUserIdentifier());
        $this->assertEquals("hash:b", $users['b']->getPassword());
        $this->assertEquals(
            ['ROLE_USER', 'ROLE_ADMIN'],
            $users['b']->getRoles()
        );

        $this->assertEquals('x', $users['x']->getUserIdentifier());
        $this->assertEquals("hash:x", $users['x']->getPassword());
        $this->assertEquals(['ROLE_XER'], $users['x']->getRoles());
    }
}
