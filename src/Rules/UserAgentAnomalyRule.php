<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Rules;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
/**
 * Detects automated security scanners and hostile bot user-agents.
 * Empty User-Agent is flagged as anomaly — legitimate browsers always send one.
 */
class UserAgentAnomalyRule extends AbstractDetectionRule
{
    public function identifier(): string
    {
        return 'user_agent_anomaly';
    }

    public function name(): string
    {
        return 'Automated Security Scanner & Bot UA Detector';
    }

    /**
     * Known automated security scanning tools.
     *
     * @var array<string, string>
     */
    protected array $scannerSignatures = [
        'sqlmap' => '/\bsqlmap\b/i',
        'nikto' => '/\bnikto\b/i',
        'dirbuster' => '/\bdirbuster\b/i',
        'gobuster' => '/\bgobuster\b/i',
        'wpscan' => '/\bwpscan\b/i',
        'masscan' => '/\bmasscan\b/i',
        'nmap' => '/\bnmap(\s+scripting\s+engine)?\b/i',
        'acunetix' => '/\bacunetix\b/i',
        'nessus' => '/\bnessus\b/i',
        'nuclei' => '/\bnuclei\b/i',
        'zgrab' => '/\bzgrab\b/i',
        'hydra' => '/\bhydra\b/i',
        // Additional hostile scanning & scraping tooling (aggressive bot hunting)
        'ffuf' => '/\bffuf\b/i',
        'dirsearch' => '/\bdirsearch\b/i',
        'zmap' => '/\bzmap\b/i',
        'cadaver' => '/\bcadaver\b/i',
        'wfuzz' => '/\bwfuzz\b/i',
        'testssl' => '/\btestssl(\.sh)?\b/i',
        'whatweb' => '/\bwhatweb\b/i',
        'sublist3r' => '/\bsublist3r\b/i',
        'katana' => '/\bkatana(\s+v[0-9])?\b/i',
        'jaeles' => '/\bjaeles\b/i',
        'dalfox' => '/\bdalfox\b/i',
        'xsstrike' => '/\bxsstrike\b/i',
        'commix' => '/\bcommix\b/i',
        'tplmap' => '/\btplmap\b/i',
        'arachni' => '/\barachni\b/i',
        'wapiti' => '/\bwapiti\b/i',
    ];

    public function evaluate(SecurityEvent $event): ?SecurityThreat
    {
        if (!$this->isEnabled()) {
            return null;
        }

        $ua = $event->userAgent;
        $blockEmptyUa = (bool) config('security-defense.detection.rules.user_agent_anomaly.block_empty_user_agent', false);

        // Flag empty User-Agent as anomaly when configured
        if (trim($ua) === '' && $blockEmptyUa) {
            $fingerprint = hash('sha256', sprintf('user_agent_anomaly:empty_ua:%s', $event->ip));

            return new SecurityThreat(
                severity: (string) $this->getConfig('severity', 'medium'),
                threatType: 'user_agent_anomaly',
                fingerprint: $fingerprint,
                metadata: [
                    'ip' => $event->ip,
                    'detected_tool' => 'empty_ua',
                    'user_agent' => '',
                    'path' => $event->metadata['path'] ?? null,
                ],
                ruleIdentifier: $this->identifier()
            );
        }

        if (trim($ua) === '') {
            return null;
        }

        $scannerTool = $this->identifyScanner($ua);

        if ($scannerTool !== null) {
            $fingerprint = hash('sha256', sprintf('user_agent_anomaly:%s:%s', $scannerTool, $event->ip));

            return new SecurityThreat(
                severity: (string) $this->getConfig('severity', 'medium'),
                threatType: 'user_agent_anomaly',
                fingerprint: $fingerprint,
                metadata: [
                    'ip' => $event->ip,
                    'detected_tool' => $scannerTool,
                    'user_agent' => $ua,
                    'path' => $event->metadata['path'] ?? null,
                ],
                ruleIdentifier: $this->identifier()
            );
        }

        return null;
    }

    /**
     * Identify scanner name from user-agent string.
     */
    public function identifyScanner(string $userAgent): ?string
    {
        foreach ($this->scannerSignatures as $toolName => $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return $toolName;
            }
        }

        return null;
    }
}
