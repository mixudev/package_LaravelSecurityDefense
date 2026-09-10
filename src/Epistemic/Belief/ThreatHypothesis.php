<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Belief;

enum ThreatHypothesis: string
{
    case ACCOUNT_COMPROMISE  = 'account_compromise';
    case CREDENTIAL_STUFFING = 'credential_stuffing';
    case SESSION_HIJACK      = 'session_hijack';
    case BRUTE_FORCE_ATTACK  = 'brute_force_attack';
    case DATA_EXFILTRATION   = 'data_exfiltration';
    case INSIDER_THREAT      = 'insider_threat';
    case AUTOMATED_SCRAPING  = 'automated_scraping';
    case IMPOSSIBLE_TRAVEL   = 'impossible_travel';
    case PAYLOAD_ATTACK      = 'payload_attack';
    case BOT_ACTIVITY        = 'bot_activity';
    case COMPOUND_ATTACK     = 'compound_attack';
    case UNKNOWN             = 'unknown';
}
