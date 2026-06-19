// ============================================================
// FILE: SoftTokenInit.js  (NEW — External Soft Token)
// Called when user clicks "Soft Token" on MFA selection page
// Routes to: download page (first time) or QR scan page
// ============================================================

importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importMappingRule("00_config");
importMappingRule("audit_utilities");
importClass(Packages.com.tivoli.am.fim.registrations.MechanismRegistrationHelper);

IDMappingExtUtils.traceString("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
IDMappingExtUtils.traceString("!!!!!!!!!!Inside SoftTokenInit!!!!!!!!!!");
IDMappingExtUtils.traceString("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

// ── Get user attributes ───────────────────────────────────
var username = context.get(
    Scope.REQUEST,
    "urn:ibm:security:asf:request:token:attribute",
    "username"
);
var fullName = context.get(
    Scope.REQUEST,
    "urn:ibm:security:asf:request:token:attribute",
    "fullName"
);

IDMappingExtUtils.traceString("SoftTokenInit - username: " + username);
IDMappingExtUtils.traceString("SoftTokenInit - fullName: " + fullName);

// ── Set username macro for QR scan page greeting ─────────
macros.put("@USERNAME@", fullName);

// ── Check TOTP enrollment status ─────────────────────────
var isTotpEnrolled = MechanismRegistrationHelper.isTotpEnrolled(username);
IDMappingExtUtils.traceString("SoftTokenInit - isTotpEnrolled: " + isTotpEnrolled);

macros.put("@CHECK@", "init");
if (isTotpEnrolled != null && isTotpEnrolled.toString() == "true") {
    macros.put("@CHECK@", isTotpEnrolled.toString());
}

// ── Get pass parameter ────────────────────────────────────
// pass=1 → not used directly here (sent from download page via reregister=1)
// pass=2 → user clicked Next on QR scan page → proceed to TOTP verify
var pass = context.get(
    Scope.REQUEST,
    "urn:ibm:security:asf:request:parameter",
    "pass"
);

// ── Get reregister parameter ─────────────────────────────
// reregister=1 → sent from download page → go to QR scan page
var reregister = context.get(
    Scope.REQUEST,
    "urn:ibm:security:asf:request:parameter",
    "reregister"
);

IDMappingExtUtils.traceString("SoftTokenInit - pass: " + pass + ", reregister: " + reregister);

var result = false;

// ── Routing logic ─────────────────────────────────────────

// Case 1: User is already enrolled → skip enrollment, go straight to TOTP verify
if (isTotpEnrolled != null && isTotpEnrolled.toString() == "true") {
    IDMappingExtUtils.traceString("SoftTokenInit - user already enrolled, proceeding to TOTP verify");
    auditSuccess("SOFT_TOKEN","SUCCESS","User already enrolled in TOTP, proceeding to verify");
    result = true;
    success.setValue(result);
}

// Case 2: reregister=1 (Next clicked on download page) → show QR scan page
else if (reregister == "1") {
    IDMappingExtUtils.traceString("SoftTokenInit - reregister=1, routing to QR scan page");
    auditSuccess("SOFT_TOKEN","SUCCESS","Routing to QR scan page after download page");
    page.setValue("/ext_otp/softtokenScanQR.html");
    result = false;
}

// Case 3: pass=2 (Next clicked on QR scan page) → proceed to TOTP verify
else if (pass == "2") {
    IDMappingExtUtils.traceString("SoftTokenInit - pass=2, proceeding to TOTP verify");
    auditSuccess("SOFT_TOKEN","SUCCESS","QR scanned, proceeding to TOTP code entry");
    result = true;
}

// Case 4: First time (no pass, not enrolled) → show download page
else {
    IDMappingExtUtils.traceString("SoftTokenInit - first time, routing to download page");
    auditSuccess("SOFT_TOKEN","SUCCESS","First time soft token setup, routing to download page");
    page.setValue("/ext_otp/softtoken_download.html");
    result = false;
}

macros.put("@WIN@", "reg");
macros.put("@COPYRIGHT@", COPYRIGHTS_MSG);
macros.put("@REFRESH@",   REDIRECTION);

success.setValue(result);