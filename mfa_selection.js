// ============================================================
// FILE: 00_mfaSelection.js  (UPDATED for Soft Token)
// Only the soft token additions are new — all existing
// email/SMS logic is preserved exactly as-is
// ============================================================

importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importMappingRule("00_config");
importMappingRule("00_config_si");
importMappingRule("00_config_ta");

importPackage(Packages.com.ibm.security.access.ciclient);
importPackage(Packages.com.ibm.security.access.server_connections);
importClass(Packages.com.ibm.security.access.user.UserLookupHelper);

// ── NEW: needed for TOTP enrollment check ──────────────────
importClass(Packages.com.tivoli.am.fim.registrations.MechanismRegistrationHelper);

importMappingRule("CI_Common");
importMappingRule("CI_Enrollment_Methods");
importMappingRule("audit_utilities");

IDMappingExtUtils.traceString("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
IDMappingExtUtils.traceString("!!!!!!!!!!Inside 00_mfaSelection!!!!!!!!!!");
IDMappingExtUtils.traceString("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

var auth      = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:token:attribute", "AZN_CRED_AUTH_METHOD");
var mobile    = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "mobileNumber");
var mail      = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "emailAddress");
var username  = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:token:attribute", "username");
var user      = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "fullName");
var authTypes = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "authenticationTypes");

IDMappingExtUtils.traceString("auth is: " + auth);
IDMappingExtUtils.traceString("authTypes is " + authTypes);

macros.put("@OTP_HIDE_SMS@",       "hidden");
macros.put("@OTP_HIDE_EMAIL@",     "hidden");
// ── NEW: default soft token to hidden ──────────────────────
macros.put("@OTP_HIDE_SOFTTOKEN@", "hidden");

var pass   = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "otp.user.type");
var result = false;

// ── URL Redirection ────────────────────────────────────────
var setTarURL = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "urlInSession");
IDMappingExtUtils.traceString("Target URL is " + setTarURL);
macros.put("@URLREDIRECTION@", setTarURL);

var forcePwdChange = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "forcePwdChange");
IDMappingExtUtils.traceString("forcePwdChange value eka is " + forcePwdChange);

var userMob  = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "mobileNumber");
var userMail = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "emailAddress");
var mfaConfig = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "mfaConfig");
var mfaObj    = JSON.parse(mfaConfig);

// ── MFA Config Parsing ────────────────────────────────────
if (mfaConfig && mfaConfig.trim() !== "") {
    try {
        var mfaObj = JSON.parse(mfaConfig);

        IDMappingExtUtils.traceString("userMob value is mobile: " + mobile);
        IDMappingExtUtils.traceString("userMail value is email: " + mail);

        var trueCount     = 0;
        var autoSubmitType = null;

        for (var key in mfaObj) {
            if (mfaObj.hasOwnProperty(key) && mfaObj[key] === true) {
                trueCount++;
                autoSubmitType = key;
                IDMappingExtUtils.traceString("the key of autoSubmitType " + autoSubmitType);
            }
        }

        var mfaFlag = (trueCount > 1) ? "true" : "false";
        macros.put("@AUTO_SUBMIT@", mfaFlag);

        macros.put("@AUTO_SUBMIT_TYPE@",   "NONE");
        macros.put("@MFA_SINGLE_VALUE@",   "NONE");
        macros.put("@MFA_VALUE_AVAILABLE@","false");

        if (mfaFlag === "false" && autoSubmitType != null) {
            IDMappingExtUtils.traceString("Inside the 1 mfa available " + mfaFlag);

            var valueFound = false;
            var mfaValue   = null;

            if (autoSubmitType.toUpperCase() === "SMS") {
                if (mobile != null && mobile !== "") {
                    valueFound = true;
                    mfaValue   = userMob.trim();
                    IDMappingExtUtils.traceString("Inside the SMS available: valueFound=" + valueFound + ", mfaValue=" + mfaValue);
                } else {
                    valueFound = false;
                    mfaValue   = null;
                    auditFail("MFA_SELECTION","FAILED","USER SMS NOT AVAILABLE");
                    IDMappingExtUtils.traceString("Inside the SMS not available");
                }
            }

            if (autoSubmitType.toUpperCase() === "EMAIL") {
                if (mail != null && mail !== "") {
                    valueFound = true;
                    mfaValue   = userMail.trim();
                    IDMappingExtUtils.traceString("Inside the EMAIL available: valueFound=" + valueFound + ", mfaValue=" + mfaValue);
                } else {
                    valueFound = false;
                    mfaValue   = null;
                    auditFail("MFA_SELECTION","FAILED","USER EMAIL NOT AVAILABLE");
                    IDMappingExtUtils.traceString("Inside the EMAIL not available");
                }
            }

            // ── NEW: SOFT_TOKEN auto-submit check ─────────
            // Soft token never auto-submits (no delivery value needed)
            // so valueFound stays false for SOFT_TOKEN single-method
            if (autoSubmitType.toUpperCase() === "SOFT_TOKEN") {
                IDMappingExtUtils.traceString("SOFT_TOKEN is the only MFA method — no auto-submit");
                valueFound = false;
                mfaValue   = null;
            }

            macros.put("@AUTO_SUBMIT_TYPE@", autoSubmitType.toUpperCase());
            IDMappingExtUtils.traceString("The available type " + autoSubmitType.toUpperCase());

            if (valueFound) {
                macros.put("@MFA_SINGLE_VALUE@",    mfaValue);
                macros.put("@MFA_VALUE_AVAILABLE@", "true");
                IDMappingExtUtils.traceString("MFA single method value found: " + mfaValue);
            } else {
                macros.put("@MFA_SINGLE_VALUE@",    "NONE");
                macros.put("@MFA_VALUE_AVAILABLE@", "false");
                IDMappingExtUtils.traceString("MFA single method enabled but no value found!");
            }
        }

        macros.put("@MFACONFIGHIDDEN@", mfaConfig);

    } catch (e) {
        IDMappingExtUtils.traceString("Error parsing MFA JSON: " + e);
        macros.put("@MFAFLAG@", "false");
    }
} else {
    IDMappingExtUtils.traceString("No MFA configuration found.");
    macros.put("@MFAFLAG@", "false");
    auditSuccess("MFA_SELECTION","SUCCESS","THERE IS NO MFA VALUE FOUND DURING THE MFA PARSING SKIPPING MFA");
}

// ── Lock Detection (unchanged) ────────────────────────────
var ul = new UserLookupHelper();
ul.init();

var u       = ul.search("cn", username, 1);
var userObj = ul.getUserByNativeId(u[0]);

if (userObj != null) {
    var lockedOn = userObj.getAttribute("otpLockedOn");
    var islocked = false;

    if (lockedOn != null && lockedOn.trim() !== "") {
        IDMappingExtUtils.traceString("$$$$$$$$$$$$$$$$$$$$$$ Lock detection from choose page");
        IDMappingExtUtils.traceString("Lock detection" + lockedOn);
        islocked = true;
        const lockedOnTime           = fromGeneralizedTime(lockedOn).getTime();
        const currentTime            = Date.now();
        const timeDifferenceInSeconds = (currentTime - lockedOnTime) / 1000;

        macros.put("@COUNT_DOWN_TIME@", MFA_LOCKOUT_TIME_SECONDS.toString());
        macros.put("@LOCKSTATUS@", "true");

        if (timeDifferenceInSeconds < MFA_LOCKOUT_TIME_SECONDS) {
            macros.put("@EXT@", lockedOnTime.toString());
            macros.put("@REMAINING@", (MFA_LOCKOUT_TIME_SECONDS - timeDifferenceInSeconds).toString());
        } else {
            userObj.removeAttribute("otpLockedOn");
            userObj.replaceAttribute("noOfOTPAttempts",   "0");
            userObj.replaceAttribute("noOfOtpGenerates",  "0");
        }
    }
}

function fromGeneralizedTime(gtime) {
    const year    = parseInt(gtime.slice(0, 4),  10);
    const month   = parseInt(gtime.slice(4, 6),  10) - 1;
    const day     = parseInt(gtime.slice(6, 8),  10);
    const hours   = parseInt(gtime.slice(8, 10), 10);
    const minutes = parseInt(gtime.slice(10, 12),10);
    const seconds = parseInt(gtime.slice(12, 14),10);
    return new Date(Date.UTC(year, month, day, hours, minutes, seconds));
}

IDMappingExtUtils.traceString("$$$$$$$$$$$$$$$$$$$$$$ Lock detection => " + islocked);

if (authTypes.includes("A_HSM_With_MFA") && !islocked) {
    IDMappingExtUtils.traceString("$$$$$$$$$$$$$$$$$$$$$$ Lock detection inside");
    result = true;
    success.setValue(result);
}

success.setValue(result);

if (pass != null) {
    result = true;
}

// ── Show/Hide MFA buttons ─────────────────────────────────

IDMappingExtUtils.traceString("userMob value is: " + userMob);
IDMappingExtUtils.traceString("mfaObj.SMS value is: " + mfaObj.SMS);
IDMappingExtUtils.traceString("userMail value is: " + userMail);
IDMappingExtUtils.traceString("mfaObj.EMAIL value is: " + mfaObj.EMAIL);
// ── NEW ──────────────────────────────────────────────────
IDMappingExtUtils.traceString("mfaObj.SOFT_TOKEN value is: " + mfaObj.SOFT_TOKEN);

if (mfaObj.SMS || mfaObj.EMAIL || mfaObj.SOFT_TOKEN) {

    // ── SMS (unchanged) ──────────────────────────────────
    if (mfaObj.SMS) {
        IDMappingExtUtils.traceString("Inside mfaObj.SMS");
        if (userMob != "" && userMob != null) {
            macros.put("@OTP_HIDE_SMS@", "visible");
            IDMappingExtUtils.traceString("User has number " + userMob);
        } else {
            macros.put("@MESS@",    MFA_MANDATED_NONE_FOUND);
            macros.put("@MESS_SI@", MFA_MANDATED_NONE_FOUND_SI);
            macros.put("@MESS_TA@", MFA_MANDATED_NONE_FOUND_TA);
            macros.put("@OTP_DIS_SMS@",       "disabled");
            macros.put("@OTP_HIDE_SMS@",      "visible");
            macros.put("@OTP_FORBIDDEN_SMS@", "opacity-50 cursor-not-allowed");
        }
    }

    // ── EMAIL (unchanged) ────────────────────────────────
    if (mfaObj.EMAIL) {
        IDMappingExtUtils.traceString("Inside mfaObj.EMAIL");
        if (userMail != "" && userMail != null) {
            macros.put("@OTP_HIDE_EMAIL@", "visible");
            IDMappingExtUtils.traceString("User has email " + userMail);
        } else {
            macros.put("@MESS@",    MFA_MANDATED_NONE_FOUND_EMAIL);
            macros.put("@MESS_SI@", MFA_MANDATED_NONE_FOUND_EMAIL_SI);
            macros.put("@MESS_TA@", MFA_MANDATED_NONE_FOUND_EMAIL_TA);
            macros.put("@OTP_DIS_EMAIL@",       "disabled");
            macros.put("@OTP_HIDE_EMAIL@",      "visible");
            macros.put("@OTP_FORBIDDEN_EMAIL@", "opacity-50 cursor-not-allowed");
        }
    }

    // ── NEW: SOFT TOKEN visibility ────────────────────────
    if (mfaObj.SOFT_TOKEN) {
        IDMappingExtUtils.traceString("Inside mfaObj.SOFT_TOKEN");

        // Check if user is enrolled in TOTP
        var isTotpEnrolled = MechanismRegistrationHelper.isTotpEnrolled(username);
        IDMappingExtUtils.traceString("TOTP enrolled status: " + isTotpEnrolled);

        // Always show the soft token button if SOFT_TOKEN is enabled in mfaConfig
        // (even if not yet enrolled — they will enroll through the flow)
        macros.put("@OTP_HIDE_SOFTTOKEN@", "visible");
        IDMappingExtUtils.traceString("Soft Token button shown for user: " + username);

        // If enrolled — normal clickable button
        // If NOT enrolled — still show button (clicking starts enrollment flow)
        if (isTotpEnrolled == null || isTotpEnrolled.toString() != "true") {
            IDMappingExtUtils.traceString("User not yet enrolled in TOTP — enrollment flow will start on click");
        } else {
            IDMappingExtUtils.traceString("User is enrolled in TOTP — verify flow will start on click");
        }
    }

    // ── Existing combination error messages (unchanged) ──

    if (mfaObj.SMS == true && mfaObj.EMAIL == false) {
        if (userMob == "" || userMob == null) {
            IDMappingExtUtils.traceString("Sahans Theorum1");
            macros.put("@MESS@",    MFA_MANDATED_NONE_FOUND);
            macros.put("@MESS_SI@", MFA_MANDATED_NONE_FOUND_SI);
            macros.put("@MESS_TA@", MFA_MANDATED_NONE_FOUND_TA);
        } else {
            if (pass == null) {
                IDMappingExtUtils.traceString("Kisaras Theorum1");
                auditSuccess("MFA_SELECTION","SUCCESS","OTP defaulted to SMS");
            }
        }
    }

    if (mfaObj.EMAIL == true && mfaObj.SMS == false) {
        if (userMail == "" || userMail == null) {
            IDMappingExtUtils.traceString("Sahans Theorum2");
            macros.put("@MESS@",    MFA_MANDATED_NONE_FOUND_EMAIL);
            macros.put("@MESS_SI@", MFA_MANDATED_NONE_FOUND_EMAIL_SI);
            macros.put("@MESS_TA@", MFA_MANDATED_NONE_FOUND_EMAIL_TA);
        } else {
            if (pass == null) {
                IDMappingExtUtils.traceString("Kisaras Theorum2");
                auditSuccess("MFA_SELECTION","SUCCESS","OTP defaulted to EMAIL");
            }
        }
    }

    if (mfaObj.EMAIL == true && mfaObj.SMS == true) {
        if ((userMail == "" || userMail == null) && (userMob == "" || userMob == null)) {
            IDMappingExtUtils.traceString("Sahans Theorum3");
            macros.put("@MESS@",    MFA_MANDATED_NONE_FOUND_BOTH);
            macros.put("@MESS_SI@", MFA_MANDATED_NONE_FOUND_BOTH_SI);
            macros.put("@MESS_TA@", MFA_MANDATED_NONE_FOUND_BOTH_TA);
            auditFail("MFA_SELECTION","FAILED","Both Email and Mobile options enabled but no values found");
        } else {
            if (pass == null) {
                IDMappingExtUtils.traceString("Kisaras Theorum3");
                auditSuccess("MFA_SELECTION","SUCCESS","Both Email and Mobile options found");
            }
        }
    }

    if (mfaObj.EMAIL == false && mfaObj.SMS == false) {
        if ((userMail == "" || userMail == null) && (userMob == "" || userMob == null)) {
            macros.put("@MESS@",    MFA_MANDATED_NONE_FOUND_BOTH);
            macros.put("@MESS_SI@", MFA_MANDATED_NONE_FOUND_BOTH_SI);
            macros.put("@MESS_TA@", MFA_MANDATED_NONE_FOUND_BOTH_TA);
        }
        auditSuccess("MFA_SELECTION","SUCCESS","MFA SELECTION SKIPPED");
    }

} else {
    IDMappingExtUtils.traceString("Number is there but SMS OTP disabled at user level : " + mfaObj.SMS);
    var userMFASkip = "true";
    context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "userMFASkip", userMFASkip);
    result = true;
}

success.setValue(result);

// ── Standard macros (unchanged) ──────────────────────────
macros.put("@COPYRIGHT@",          COPYRIGHTS_MSG);
macros.put("@REDIRECTION_OTP_LOCK@", REDIRECTION_OTP_LOCK);
macros.put("@REFRESH@",            REDIRECTION);

macros.put("@MFALOCKONE@",          ACCOUNT_LOCKED_DUE_TO_MFA_LOCK);
macros.put("@MFALOCKONE_SI@",       ACCOUNT_LOCKED_DUE_TO_MFA_LOCK_SI);
macros.put("@MFALOCKONE_TA@",       ACCOUNT_LOCKED_DUE_TO_MFA_LOCK_TA);
macros.put("@MFALOCKTWO@",          ACCOUNT_LOCKED_DUE_TO_MFA_LOCK_2);
macros.put("@MFALOCKTWO_SI@",       ACCOUNT_LOCKED_DUE_TO_MFA_LOCK_2_SI);
macros.put("@MFALOCKTWO_TA@",       ACCOUNT_LOCKED_DUE_TO_MFA_LOCK_2_TA);
macros.put("@MFALOCKTEMP@",         NO_ATTEMPTS_REMAINING);
macros.put("@MFALOCKTEMP_SI@",      NO_ATTEMPTS_REMAINING_SI);
macros.put("@MFALOCKTEMP_TA@",      NO_ATTEMPTS_REMAINING_TA);
macros.put("@MFALOCKTEMPREMAIN@",   NO_ATTEMPTS_REMAINING_REMAIN);
macros.put("@MFALOCKTEMPREMAIN_SI@",NO_ATTEMPTS_REMAINING_REMAIN_SI);
macros.put("@MFALOCKTEMPREMAIN_TA@",NO_ATTEMPTS_REMAINING_REMAIN_TA);

IDMappingExtUtils.traceString("MAIL IS meow: " + mail);

var authTypes = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "authenticationTypes");
IDMappingExtUtils.traceString("Authn Levels 20251120: " + authTypes);