importPackage(Packages.com.tivoli.am.fim.trustserver.sts.utilities);
    importClass(Packages.com.ibm.security.access.user.UserLookupHelper);
    importClass(Packages.com.ibm.security.access.user.User);
    importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
    importClass(Packages.com.tivoli.am.fim.registrations.MechanismRegistrationHelper);
    importClass(Packages.com.tivoli.am.fim.authsvc.local.client.AuthSvcClient);

    var reregister = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "reregister");
    var otppswd = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "otppswd");
    var secretKey = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "secretKey");
    var username = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:token:attribute", "username");
    var fullName =  context.get(Scope.REQUEST, "urn:ibm:security:asf:request:token:attribute", "fullName");
    var errorString = "";
    var status = false;


        var lockout = 900;



    // DMA Cache and Counter Setup
    var dmapCache = IDMappingExtUtils.getIDMappingExtCache();
    var reattemptCounterID = "otpValidation_" + username; // Unique key per user
    var maxAttempts = 3; // Max allowed reattempts
    var currentCounter = 0;

    // Initialize counter from cache or default to 0
    if (dmapCache.exists(reattemptCounterID)) {
        currentCounter = parseInt(dmapCache.get(reattemptCounterID));
    }
     macros.put("@USERNAME@", "Hello " + fullName);
    // Check if user is TOTP enrolled
    if (reregister == "1") {
        page.setValue("/a_otp/initial_qr.html");
    }

    IDMappingExtUtils.traceString("In TOTP: " + reregister );

    if (!MechanismRegistrationHelper.isTotpEnrolled(username) && (reregister != "1")) {
        errorString = "User is not enrolled in TOTP.";
        page.setValue("/authsvc/SoftTokenDownload.html");
    } else {
        if (otppswd == null) {
            var otpSecret = secretKey;
            success.setValue(false);
        } else {
            var otpSecret = secretKey;

            // Construct payload for validation
            var payload = "{ \"PolicyId\": \"urn:ibm:security:authentication:asf:internalTOTPValidation\", " +
                          "\"username\": \"" + username + "\", " +
                          "\"operation\": \"verify\", " +
                          "\"secretKey\": \"" + otpSecret + "\", " +
                          "\"otp\": \"" + otppswd + "\" }";

            var resp = AuthSvcClient.execute(payload);
            var response = JSON.parse(resp);

            // Debugging
            var debugString = "Validation Debug: secret=" + otpSecret + ", Payload=" + payload + ", Response=" + resp;
            IDMappingExtUtils.traceString(debugString);

            macros.put("@MESSAGE@", debugString);

            if (response.status == "success") {
                status = true; // OTP is valid
                // Reset the reattempt counter on success
                dmapCache.put(reattemptCounterID, 0, lockout);
            } else {
                // OTP validation failed, increment counter
                currentCounter += 1;
                if (currentCounter >= maxAttempts) {
                    macros.put("@ERROR_MESSAGE@", errorString);
                    macros.put("@CURRENT_ATTEMPTS@", currentCounter.toString());
                    success.setValue(status);

                    dmapCache.put(reattemptCounterID, currentCounter, lockout);
                    errorString = "Maximum OTP attempts exceeded. wait 900 seconds";
                   //dmapCache.getAndRemove(reattemptCounterID);
                    var ext= username;
                    var cc = Date.now();
                    dmapCache.put(ext, cc, 900);    
                    dmapCache.put(reattemptCounterID, currentCounter, 900);

                } else {
                    dmapCache.put(reattemptCounterID, currentCounter, lockout);
                    errorString = "Invalid Security code. Please Try Again. - You have " + (maxAttempts - currentCounter) + " attempts remaining.";
                }
            }
        }
    }

    // Set macros for the UI
    macros.put("@ERROR_MESSAGE@", errorString);
    macros.put("@CURRENT_ATTEMPTS@", currentCounter.toString());
    success.setValue(status);