﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Enums
{
    [Flags]
    public enum UACEnum : UInt64
    {
        SCRIPT = 1,
        NOT_SCRIPT = SCRIPT * 2,
        ACCOUNTDISABLE = NOT_SCRIPT * 2,
        NOT_ACCOUNTDISABLE = ACCOUNTDISABLE * 2,
        HOMEDIR_REQUIRED = NOT_ACCOUNTDISABLE * 2,
        NOT_HOMEDIR_REQUIRED = HOMEDIR_REQUIRED * 2,
        LOCKOUT = NOT_HOMEDIR_REQUIRED * 2,
        NOT_LOCKOUT = LOCKOUT * 2,
        PASSWD_NOTREQD = NOT_LOCKOUT * 2,
        NOT_PASSWD_NOTREQD = PASSWD_NOTREQD * 2,
        PASSWD_CANT_CHANGE = NOT_PASSWD_NOTREQD * 2,
        NOT_PASSWD_CANT_CHANGE = PASSWD_CANT_CHANGE * 2,
        ENCRYPTED_TEXT_PWD_ALLOWED = NOT_PASSWD_CANT_CHANGE * 2,
        NOT_ENCRYPTED_TEXT_PWD_ALLOWED = ENCRYPTED_TEXT_PWD_ALLOWED * 2,
        TEMP_DUPLICATE_ACCOUNT = NOT_ENCRYPTED_TEXT_PWD_ALLOWED * 2,
        NOT_TEMP_DUPLICATE_ACCOUNT = TEMP_DUPLICATE_ACCOUNT * 2,
        NORMAL_ACCOUNT = NOT_TEMP_DUPLICATE_ACCOUNT * 2,
        NOT_NORMAL_ACCOUNT = NORMAL_ACCOUNT * 2,
        INTERDOMAIN_TRUST_ACCOUNT = NOT_NORMAL_ACCOUNT * 2,
        NOT_INTERDOMAIN_TRUST_ACCOUNT = INTERDOMAIN_TRUST_ACCOUNT * 2,
        WORKSTATION_TRUST_ACCOUNT = NOT_INTERDOMAIN_TRUST_ACCOUNT * 2,
        NOT_WORKSTATION_TRUST_ACCOUNT = WORKSTATION_TRUST_ACCOUNT * 2,
        SERVER_TRUST_ACCOUNT = NOT_WORKSTATION_TRUST_ACCOUNT * 2,
        NOT_SERVER_TRUST_ACCOUNT = SERVER_TRUST_ACCOUNT * 2,
        DONT_EXPIRE_PASSWORD = NOT_SERVER_TRUST_ACCOUNT * 2,
        NOT_DONT_EXPIRE_PASSWORD = DONT_EXPIRE_PASSWORD * 2,
        MNS_LOGON_ACCOUNT = NOT_DONT_EXPIRE_PASSWORD * 2,
        NOT_MNS_LOGON_ACCOUNT = MNS_LOGON_ACCOUNT * 2,
        SMARTCARD_REQUIRED = NOT_MNS_LOGON_ACCOUNT * 2,
        NOT_SMARTCARD_REQUIRED = SMARTCARD_REQUIRED * 2,
        TRUSTED_FOR_DELEGATION = NOT_SMARTCARD_REQUIRED * 2,
        NOT_TRUSTED_FOR_DELEGATION = TRUSTED_FOR_DELEGATION * 2,
        NOT_DELEGATED = NOT_TRUSTED_FOR_DELEGATION * 2,
        NOT_NOT_DELEGATED = NOT_DELEGATED * 2,
        USE_DES_KEY_ONLY = NOT_NOT_DELEGATED * 2,
        NOT_USE_DES_KEY_ONLY = USE_DES_KEY_ONLY * 2,
        DONT_REQ_PREAUTH = NOT_USE_DES_KEY_ONLY * 2,
        NOT_DONT_REQ_PREAUTH = DONT_REQ_PREAUTH * 2,
        PASSWORD_EXPIRED = NOT_DONT_REQ_PREAUTH * 2,
        NOT_PASSWORD_EXPIRED = PASSWORD_EXPIRED * 2,
        TRUSTED_TO_AUTH_FOR_DELEGATION = NOT_PASSWORD_EXPIRED * 2,
        NOT_TRUSTED_TO_AUTH_FOR_DELEGATION = TRUSTED_TO_AUTH_FOR_DELEGATION * 2,
        PARTIAL_SECRETS_ACCOUNT = NOT_TRUSTED_TO_AUTH_FOR_DELEGATION * 2,
        NOT_PARTIAL_SECRETS_ACCOUNT = PARTIAL_SECRETS_ACCOUNT * 2
    }

    [Flags]
    public enum UACEnumValue : Int32
    {
        SCRIPT = 1,
        ACCOUNTDISABLE = 2,
        HOMEDIR_REQUIRED = 8,
        LOCKOUT = 16,
        PASSWD_NOTREQD = 32,
        PASSWD_CANT_CHANGE = 64,
        ENCRYPTED_TEXT_PWD_ALLOWED = 128,
        TEMP_DUPLICATE_ACCOUNT = 256,
        NORMAL_ACCOUNT = 512,
        INTERDOMAIN_TRUST_ACCOUNT = 2048,
        WORKSTATION_TRUST_ACCOUNT = 4096,
        SERVER_TRUST_ACCOUNT = 8192,
        DONT_EXPIRE_PASSWORD = 65536,
        MNS_LOGON_ACCOUNT = 131072,
        SMARTCARD_REQUIRED = 262144,
        TRUSTED_FOR_DELEGATION = 524288,
        NOT_DELEGATED = 1048576,
        USE_DES_KEY_ONLY = 2097152,
        DONT_REQ_PREAUTH = 4194304,
        PASSWORD_EXPIRED = 8388608,
        TRUSTED_TO_AUTH_FOR_DELEGATION = 16777216,
        PARTIAL_SECRETS_ACCOUNT = 67108864
    }
}
