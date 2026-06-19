// ============================================================
// FILE: SoftTokenVerify.js  (NEW — External Soft Token)
// Called when user submits 6-digit code on softtokenTOTP.html
// Pattern matches your existing OTPVerify.js exactly
// ============================================================

importClass(Packages.com.tivoli.am.fim.trustserver.sts.uuser.Attribute);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.ibm.security.access.user.UserLookupHelper);
importClass(Packages.com.tivoli.am.fim.registrations.MechanismRegistrationHelper);
importClass(Packages.com.tivoli.am.fim.authsvc.local.client.AuthSvcClient);

importMappingRule("00_config");
importMappingRule("00_config_si");
importMappingRule("00_config_ta");
importMappingRule("00_utilities");
importMappingRule("00_audit_utill");

IDMappingExtUtils.traceString("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
IDMappingExtUtils.traceString("!!!!!!!!!!Inside SoftTokenVerify!!!!!!!!!!");
IDMappingExtUtils.traceString("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

// ── Uses stsuuCtxAttrs pattern — same as your OTPVerify.js ─
var stsuuAttrs    = stsuu.getAttributeContainer();
var stsuuCtxAttrs = stsuu.getContextAttributesAttributeContainer();

// ── Get user ─────────────────────────────────────────────
var username = stsuu.getAttributeValueByName("AZN_CRED_PRINCIPAL_NAME");
var fullName = stsuuAttrs.getAttributeValueByName("fullName");

IDMappingExtUtils.traceString("SoftTokenVerify - username: " + username);

if (username == null || username.trim() == "") {
    username = "Unknown User";
    IDMappingExtUtils.traceString("No username found during SoftTokenVerify");
}

// ── Get submitted OTP fields ──────────────────────────────
// These come from softtokenTOTP.html hidden fields
var otppswd    = stsuu.getContextAttributeValueByNameAndType(
    "otppswd", "urn:ibm:security:asf:request:parameter"
);
var secretKey  = stsuu.getContextAttributeValueByNameAndType(
    "secretKey", "urn:ibm:security:asf:request:parameter"
);
var reregister = stsuu.getContextAttributeValueByNameAndType(
    "reregister", "urn:ibm:security:asf:request:parameter"
);

IDMappingExtUtils.traceString("SoftTokenVerify - otppswd: " + otppswd);
IDMappingExtUtils.traceString("SoftTokenVerify - reregister: " + reregister);

// ── Set username macro ────────────────────────────────────
stsuuCtxAttrs.setAttribute(new Attribute("@USERNAME@", "otp.sts.macro.type", fullName));

// ── mfaConfig — same pattern as OTPVerify.js ─────────────
var mfaConfig = stsuu.getAttributeValueByName("mfaConfig");

if (mfaConfig && mfaConfig.trim() !== "") {
    try {
        var mfaObj = JSON.parse(mfaConfig);

        var trueCount = 0;
        var smsTrueFalse       = mfaObj.SMS;
        if (smsTrueFalse === true || smsTrueFalse === "true")         trueCount++;
        var emailTrueFalse     = mfaObj.EMAIL;
        if (emailTrueFalse === true || emailTrueFalse === "true")     trueCount++;
        var softTokenTrueFalse = mfaObj.SOFT_TOKEN;
        if (softTokenTrueFalse === true || softTokenTrueFalse === "true") trueCount++;
        var fidoTrueFalse      = mfaObj.FIDO;
        if (fidoTrueFalse === true || fidoTrueFalse === "true")       trueCount++;

        var mfaFlag = (trueCount >= 2) ? "true" : "false";
        stsuuCtxAttrs.setAttribute(new Attribute("@MFAFLAG@",        "otp.sts.macro.type", mfaFlag));
        stsuuCtxAttrs.setAttribute(new Attribute("@MFACONFIGHIDDEN@","otp.sts.macro.type", mfaConfig));

        IDMappingExtUtils.traceString("SoftTokenVerify - MFA flag: " + mfaFlag);

    } catch (e) {
        IDMappingExtUtils.traceString("Error parsing MFA JSON in SoftTokenVerify: " + e);
        stsuuCtxAttrs.setAttribute(new Attribute("@MFAFLAG@", "otp.sts.macro.type", "false"));
    }
} else {
    stsuuCtxAttrs.setAttribute(new Attribute("@MFAFLAG@", "otp.sts.macro.type", "false"));
}

// ── Routing: reregister=2 → back to QR scan page ─────────
// "Re-Register a Device" button on softtokenTOTP.html sends reregister=2
if (reregister == "2") {
    IDMappingExtUtils.traceString("SoftTokenVerify - re-register requested, routing to QR scan page");
    auditSuccess("SOFT_TOKEN","SUCCESS","User requested re-registration, routing to QR scan");
    page.setValue("/ext_otp/softtokenScanQR.html");
    success.setValue(false);
    return;
}

// ── Check enrollment ──────────────────────────────────────
if (!MechanismRegistrationHelper.isTotpEnrolled(username)) {
    IDMappingExtUtils.traceString("SoftTokenVerify - user not enrolled, routing to download page");
    auditFail("SOFT_TOKEN","FAILED","User not enrolled in TOTP, routing to download page");
    page.setValue("/ext_otp/softtoken_download.html");
    success.setValue(false);
    return;
}

// ── User Lookup — same as OTPVerify.js ───────────────────
var ul = new UserLookupHelper();
ul.init();

var u       = ul.search("cn", username, 1);
var userObj = ul.getUserByNativeId(u[0]);

if (userObj == null || userObj == "") {
    IDMappingExtUtils.traceString("SoftTokenVerify - userObj is empty");
    auditFail("SOFT_TOKEN","FAILED","User not found in ISDS during SoftTokenVerify");
    success.setValue(false);
    return;
}

// ── Lock check — same pattern as OTPVerify.js ────────────
var currentAttempts = parseInt(userObj.getAttribute("noOfOTPAttempts")) || 0;
var lockedOn        = userObj.getAttribute("otpLockedOn");
var isLocked        = false;
var maxAttempts     = INVALID_OTP_ATTEMPTS + 1;

if (lockedOn != null && lockedOn.trim() !== "") {
    isLocked = true;
    IDMappingExtUtils.traceString("SoftTokenVerify - OTP is locked");
    auditFail("SOFT_TOKEN","FAILED","Soft Token is locked due to previous attempts");
}

// ── No OTP submitted yet (page just loaded) ───────────────
if (otppswd == null || otppswd.toString().trim() == "") {
    IDMappingExtUtils.traceString("SoftTokenVerify - no OTP submitted yet");
    success.setValue(false);
    return;
}

// ── Validate TOTP via AuthSvcClient ──────────────────────
// Same internal TOTP validation policy used in internal app
var payload = "{ \"PolicyId\": \"urn:ibm:security:authentication:asf:internalTOTPValidation\", " +
              "\"username\": \"" + username + "\", " +
              "\"operation\": \"verify\", " +
              "\"secretKey\": \"" + secretKey + "\", " +
              "\"otp\": \"" + otppswd + "\" }";

IDMappingExtUtils.traceString("SoftTokenVerify - validation payload: " + payload);

var resp     = AuthSvcClient.execute(payload);
var response = JSON.parse(resp);

IDMappingExtUtils.traceString("SoftTokenVerify - validation response: " + resp);

if (response.status == "success") {
    // ── TOTP Valid ────────────────────────────────────────
    IDMappingExtUtils.traceString("SoftTokenVerify - TOTP valid, authentication success");
    auditSuccess("SOFT_TOKEN","SUCCESS","Soft Token OTP validated successfully for user: " + username);

    // Reset attempt counter — same as OTPVerify.js
    userObj.replaceAttribute("noOfOTPAttempts", "0");
    if (lockedOn != null) {
        userObj.removeAttribute("otpLockedOn");
    }

    success.setValue(true);

} else {
    // ── TOTP Invalid: increment counter ──────────────────
    currentAttempts++;
    IDMappingExtUtils.traceString("SoftTokenVerify - TOTP invalid. Attempt " + currentAttempts + " of " + maxAttempts);

    if (currentAttempts >= maxAttempts) {
        // ── Max attempts exceeded → lock ──────────────────
        // Same pattern as OTPVerify.js
        userObj.replaceAttribute("noOfOTPAttempts", currentAttempts.toString());
        userObj.replaceAttribute("otpLockedOn", toGeneralizedTime());

        auditFail("SOFT_TOKEN","FAILED","Soft Token MFA temporarily disabled due to invalid attempts | Attempt Count: " + currentAttempts);

        stsuuCtxAttrs.setAttribute(new Attribute(
            "@MAPPING_RULE_DATA@", "otp.sts.macro.type",
            "Multifactor authentication disabled due to invalid attempts"
        ));

        if (!isLocked) {
            IDMappingExtUtils.traceString("SoftTokenVerify - locking user MFA");
            stsuuCtxAttrs.setAttribute(new Attribute("@RESET@", "otp.sts.macro.type", "RESET"));
        }

        // Set error string matching FBTOTP338E pattern
        // softtokenTOTP.html displayError() parses this
        stsuuCtxAttrs.setAttribute(new Attribute(
            "@ERROR_MESSAGE@", "otp.sts.macro.type",
            "FBTOTP338E " + NO_ATTEMPTS_REMAINING
        ));

    } else {
        // ── Still has attempts remaining ──────────────────
        userObj.replaceAttribute("noOfOTPAttempts", currentAttempts.toString());

        var remaining = maxAttempts - currentAttempts;

        // Error string matching FBTOTP337E pattern
        // softtokenTOTP.html displayError() parses this
        var errorStr = "FBTOTP337E Invalid Security code. Please Try Again. " +
                       "You have " + remaining + " attempts remaining.";

        stsuuCtxAttrs.setAttribute(new Attribute(
            "@ERROR_MESSAGE@", "otp.sts.macro.type", errorStr
        ));

        auditFail("SOFT_TOKEN","FAILED",
            "Soft Token OTP invalid for user: " + username +
            " | Remaining attempts: " + remaining
        );

        IDMappingExtUtils.traceString("SoftTokenVerify - remaining attempts: " + remaining);
    }

    success.setValue(false);
}

// ── Standard macros ───────────────────────────────────────
stsuuCtxAttrs.setAttribute(new Attribute("@COPYRIGHT@", "otp.sts.macro.type", COPYRIGHTS_MSG));