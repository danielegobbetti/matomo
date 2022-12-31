<?php

/**
 * Matomo - free/libre analytics platform
 *
 * @link https://matomo.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 */

namespace Piwik\Plugins\Login\Validators;

use Piwik\API\Request;
use Piwik\Container\StaticContainer;
use Piwik\Piwik;
use Piwik\Plugins\Login\SystemSettings;
use Piwik\Validators\BaseValidator;
use Piwik\Validators\Exception;

class AllowedEmailDomain extends BaseValidator
{
    public function getDomainFromEmail($email)
    {
        return mb_strtolower(trim(mb_substr($email, mb_strrpos($email, '@') + 1)));
    }

    public function doesEmailEndWithAValidDomain($email, $domains): bool
    {
        $domains = array_map('mb_strtolower', $domains);
        $domain = $this->getDomainFromEmail($email);

        return in_array($domain, $domains, true);
    }

    public function getEmailDomainsInUse(): array
    {
        $users = Request::processRequest('UsersManager.getUsers');
        $domains = [];
        foreach ($users as $user) {
            $domains[] = AllowedEmailDomain::getDomainFromEmail($user['email']);
        }
        return array_values(array_unique($domains));
    }

    public function validate($value)
    {
        /** @var SystemSettings $settings */
        $settings = StaticContainer::get(SystemSettings::class);
        $domains = $settings->allowedEmailDomains->getValue();

        if (empty($domains)) {
            return;
        }

        if (!$this->doesEmailEndWithAValidDomain($value, $domains)) {
            throw new Exception(Piwik::translate('The email domain %1$s cannot be used for a user as only %2$s domains are allowed.', [$value, implode(',', $domains)]));
        }
    }

}
