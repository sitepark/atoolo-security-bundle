<?php declare(strict_types=1);

namespace Atoolo\Security\Test;

use Atoolo\Security\RealmPropertiesUserLoader;
use PHPUnit\Framework\TestCase;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;

/**
 * @covers \Atoolo\Security\RealmPropertiesUserLoader
 */
class RealmPropertiesUserLoaderTest extends TestCase {

	public function test() {

		$loader = new RealmPropertiesUserLoader(
			__DIR__ . '/realm.properties',
			new class() implements UserPasswordHasherInterface {
				public function hashPassword(PasswordAuthenticatedUserInterface $user, string $plainPassword): string {
					return "hash:" . $plainPassword;
				}
				public function isPasswordValid(PasswordAuthenticatedUserInterface $user, string $plainPassword): bool {
					return true;
				}
				public function needsRehash(PasswordAuthenticatedUserInterface $user): bool {
					return false;
				}
			});

		$users = $loader->load();

		$this->assertIsArray($users);
		$this->assertArrayHasKey('api', $users);

		$user = $users['api'];
		$this->assertEquals("api", $user->getUserIdentifier());
		$this->assertEquals("hash:develop", $user->getPassword());
		$this->assertEquals(['ROLE_API', 'ROLE_TEST'], $user->getRoles());
	}

}