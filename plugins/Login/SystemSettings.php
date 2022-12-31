<?php
/**
 * Matomo - free/libre analytics platform
 *
 * @link https://matomo.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 */

namespace Piwik\Plugins\Login;

use Matomo\Network\IP;
use Piwik\API\Request;
use Piwik\Piwik;
use Piwik\Plugins\Login\Validators\AllowedEmailDomain;
use Piwik\Settings\Setting;
use Piwik\Settings\FieldConfig;
use Piwik\Validators\IpRanges;

/**
 * Defines Settings for Login.
 */
class SystemSettings extends \Piwik\Settings\Plugin\SystemSettings
{
    /** @var Setting */
    public $enableBruteForceDetection;

    /** @var Setting */
    public $whitelisteBruteForceIps;

    /** @var Setting */
    public $blacklistedBruteForceIps;

    /** @var Setting */
    public $maxFailedLoginsPerMinutes;

    /** @var Setting */
    public $loginAttemptsTimeRange;

    /** @var Setting */
    public $allowedEmailDomains;

    protected function init()
    {
        $this->allowedEmailDomains = $this->createAllowedEmailDomains();
        $this->enableBruteForceDetection = $this->createEnableBruteForceDetection();
        $this->maxFailedLoginsPerMinutes = $this->createMaxFailedLoginsPerMinutes();
        $this->loginAttemptsTimeRange = $this->createLoginAttemptsTimeRange();
        $this->blacklistedBruteForceIps = $this->createBlacklistedBruteForceIps();
        $this->whitelisteBruteForceIps = $this->createWhitelisteBruteForceIps();
    }

    private function createAllowedEmailDomains()
    {
        return $this->makeSetting('allowedEmailDomains', array(), FieldConfig::TYPE_ARRAY, function (FieldConfig $field) {
            $field->title = 'Restrict login email domains';
            $field->uiControl = FieldConfig::UI_CONTROL_FIELD_ARRAY;
            $arrayField = new FieldConfig\ArrayField('Allowed email domain', FieldConfig::UI_CONTROL_TEXT);
            $field->uiControlAttributes['field'] = $arrayField->toArray();
            $field->description = 'When configured, then only the defined email domains can be used when inviting, adding, or updating users. It helps for privacy as it prevents unwanted data sharing with third parties. It can also helps from a security point of view to prevent users from changing their email address to a personal email, and it can act as an additional layer to prevent various security attacks.';

            $allowedEmailDomains = new AllowedEmailDomain();
            $domainsInUse = $allowedEmailDomains->getEmailDomainsInUse();
            $field->inlineHelp .= '<strong>Currently, these email domains are in use:</strong><br>' . implode('<br>', $domainsInUse);

            $field->validate = function ($value) use ($field, $allowedEmailDomains) {
                if (empty($value)) {
                    return;
                }
                $value = call_user_func($field->transform, $value, $this);
                $domainsInUse = $allowedEmailDomains->getEmailDomainsInUse();

                $notMatchingDomains = array_diff($domainsInUse, $value);
                if (!empty($notMatchingDomains)) {
                    $notMatchingDomains = implode(',', array_unique($notMatchingDomains));
                    $message = sprintf('Setting the domains is not possible as other domains (%s) are already in use by other users. To change this setting, you either need to delete users with other domains or you need to allow these domains as well.', $notMatchingDomains);
                    throw new \Exception($message);
                }
            };
            $field->transform = function ($domains) {
                if (empty($domains)) {
                    return array();
                }

                if (!is_array($domains)){
                    $domains = [$domains];
                }

                $domains = array_map(function ($domain) {
                    $domain = trim($domain);
                    return mb_strtolower(trim(ltrim($domain, '@')));
                }, $domains);
                $domains = array_filter($domains, 'strlen');
                $domains = array_unique($domains);
                $domains = array_values($domains);
                return $domains;
            };
        });
    }

    private function createEnableBruteForceDetection()
    {
        return $this->makeSetting('enableBruteForceDetection', $default = true, FieldConfig::TYPE_BOOL, function (FieldConfig $field) {
            $field->title = Piwik::translate('Login_SettingBruteForceEnable');
            $field->description = Piwik::translate('Login_SettingBruteForceEnableHelp');
            $field->uiControl = FieldConfig::UI_CONTROL_CHECKBOX;
        });
    }

    private function createWhitelisteBruteForceIps()
    {
        return $this->makeSetting('whitelisteBruteForceIps', array(), FieldConfig::TYPE_ARRAY, function (FieldConfig $field) {
            $field->title = Piwik::translate('Login_SettingBruteForceWhitelistIp');
            $field->uiControl = FieldConfig::UI_CONTROL_TEXTAREA;
            $field->description = Piwik::translate('Login_HelpIpRange', array('1.2.3.4/24', '1.2.3.*', '1.2.*.*')) . ' '. Piwik::translate('Login_NotAllowListTakesPrecendence');
            $field->validators[] = new IpRanges();
            $field->transform = function ($value) {
                if (empty($value)) {
                    return array();
                }

                $ips = array_map('trim', $value);
                $ips = array_filter($ips, 'strlen');
                $ips = array_values($ips);
                return $ips;
            };
        });
    }

    private function createBlacklistedBruteForceIps()
    {
        return $this->makeSetting('blacklistedBruteForceIps', array(), FieldConfig::TYPE_ARRAY, function (FieldConfig $field) {
            $field->title = Piwik::translate('Login_SettingBruteForceBlacklistIp');
            $field->uiControl = FieldConfig::UI_CONTROL_TEXTAREA;
            $field->description = Piwik::translate('Login_HelpIpRange', array('1.2.3.4/24', '1.2.3.*', '1.2.*.*')) . ' '. Piwik::translate('Login_NotAllowListTakesPrecendence');
            $field->validators[] = new IpRanges();
            $field->transform = function ($value) {
                if (empty($value)) {
                    return array();
                }

                $ips = array_map('trim', $value);
                $ips = array_filter($ips, 'strlen');
                $ips = array_values($ips);
                return $ips;
            };
        });
    }

    private function createMaxFailedLoginsPerMinutes()
    {
        return $this->makeSetting('maxAllowedRetries', 20, FieldConfig::TYPE_INT, function (FieldConfig $field) {
            $field->title = Piwik::translate('Login_SettingBruteForceMaxFailedLogins');
            $field->uiControl = FieldConfig::UI_CONTROL_TEXT;
            $field->description = Piwik::translate('Login_SettingBruteForceMaxFailedLoginsHelp');
        });
    }

    private function createLoginAttemptsTimeRange()
    {
        return $this->makeSetting('allowedRetriesTimeRange', 60, FieldConfig::TYPE_INT, function (FieldConfig $field) {
            $field->title = Piwik::translate('Login_SettingBruteForceTimeRange');
            $field->description = Piwik::translate('Login_SettingBruteForceTimeRangeHelp');
            $field->uiControl = FieldConfig::UI_CONTROL_TEXT;
        });
    }

    public function isWhitelistedIp($ipAddress)
    {
        return $this->isIpInList($ipAddress, $this->whitelisteBruteForceIps->getValue());
    }

    public function isBlacklistedIp($ipAddress)
    {
        return $this->isIpInList($ipAddress, $this->blacklistedBruteForceIps->getValue());
    }

    private function isIpInList($ipAddress, $ips)
    {
        if (empty($ipAddress)) {
            return false;
        }

        $ip = IP::fromStringIP($ipAddress);

        if (empty($ips)) {
            return false;
        }

        return $ip->isInRanges($ips);
    }
}
