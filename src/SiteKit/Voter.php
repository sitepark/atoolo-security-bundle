<?php

declare(strict_types=1);

namespace Atoolo\Security\SiteKit;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter as VoterBase;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use Symfony\Component\Security\Http\AccessMapInterface;

class Voter extends VoterBase implements VoterInterface
{
    public const SITEKIT_PUBLICATION = 'SITEKIT_PUBLICATION';

    /**
     * @var AccessMapInterface $accessMap
     */
    private $accessMap;

    public function __construct(AccessMapInterface $accessMap)
    {
        $this->accessMap = $accessMap;
    }

    /**
     * @param mixed $subject
     */
    protected function supports(string $attribute, $subject): bool
    {
        return $attribute === self::SITEKIT_PUBLICATION;
    }

    /**
     * @param mixed $subject
     */
    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): bool
    {

        if (!($subject instanceof Request)) {
            return false;
        }

        $roles = $this->accessMap->getPatterns($subject)[0];

        if ($roles === null || count($roles) === 0) {
            return true;
        }

        $roleMatches = array_intersect($roles, $token->getRoleNames());

        return count($roleMatches) > 0;
    }
}
