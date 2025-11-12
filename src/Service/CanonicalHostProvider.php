<?php

declare(strict_types=1);

namespace Atoolo\Security\Service;

interface CanonicalHostProvider
{
    public function getCanonicalHost(): ?string;
}
