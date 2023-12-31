<?php

declare(strict_types=1);

namespace Atoolo\Security;

use Symfony\Component\Config\Loader\GlobFileLoader;
use Symfony\Component\Config\Loader\LoaderResolver;
use Symfony\Component\DependencyInjection\Loader\XmlFileLoader;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class AtooloSecurityBundle extends Bundle
{
    public function build(ContainerBuilder $container): void
    {
        $configDir = __DIR__ . '/Resources/config';

        $loader = new GlobFileLoader(new FileLocator($configDir));
        $loader->setResolver(
            new LoaderResolver(
                [
                    new YamlFileLoader($container, new FileLocator($configDir)),
                ]
            )
        );

        $loader->load('services.yaml');
        $loader->load('packages/*.yaml', 'glob');
    }
}
