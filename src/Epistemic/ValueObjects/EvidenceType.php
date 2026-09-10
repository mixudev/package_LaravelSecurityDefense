<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\ValueObjects;

enum EvidenceType: string
{
    case LOGIN_FAILED          = 'login_failed';
    case LOGIN_SUCCESS         = 'login_success';
    case NEW_DEVICE            = 'new_device';
    case NEW_LOCATION          = 'new_location';
    case OTP_FAILED            = 'otp_failed';
    case PASSWORD_RESET        = 'password_reset';
    case RATE_LIMIT_TRIGGERED  = 'rate_limit_triggered';
    case SESSION_ANOMALY       = 'session_anomaly';
    case IP_REPUTATION         = 'ip_reputation';
    case DEVICE_REPUTATION     = 'device_reputation';
    case BEHAVIOR_ANOMALY      = 'behavior_anomaly';
    case IMPOSSIBLE_TRAVEL     = 'impossible_travel';
    case PAYLOAD_INJECTION     = 'payload_injection';
    case BRUTE_FORCE           = 'brute_force';
    case COMPOUND_THREAT       = 'compound_threat';
    case AI_SIGNAL             = 'ai_signal';
    case TRUSTED_DEVICE        = 'trusted_device';
    case TRUSTED_LOCATION      = 'trusted_location';
    case CLEAN_HISTORY         = 'clean_history';
}
