//Soft Token
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.registrations.MechanismRegistrationHelper);

var username =  context.get(Scope.REQUEST, "urn:ibm:security:asf:request:token:attribute", "username");
var fullName =  context.get(Scope.REQUEST, "urn:ibm:security:asf:request:token:attribute", "fullName");
macros.put("@USERNAME@", "Hello " + fullName);
var check = MechanismRegistrationHelper.isTotpEnrolled(username);
  macros.put("@CHECK@","init");
if(check != null && check.toString() == "true" )
{
  macros.put("@CHECK@",check.toString());
}


var result = false;



var pass = 0;
pass = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "pass");

if (pass == 1) {
 page.setValue("/a_otp/initial_qr.html");
}
if (pass == 2) {
 result = true;
//page.setValue("/authsvc/authenticator/totp/login.html");
}

if ( macros.get("@CHECK@").toString().includes("true")){
   result = true;
   success.setValue(result);
}


macros.put("@WIN@", 'reg');
success.setValue(result);