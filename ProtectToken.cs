// Generate Token and Crypto Password
public string ProtectToken(UserContextModel usercontext, HttpContext context)
 {
     //Crypto Password to sign user inputs
     string strPassword = Protect(usercontext.StaffNo + usercontext.StaffId.ToString() + usercontext.Doj);
     string IV = Protect(usercontext.StaffNo);
     string saltstr = Protect(usercontext.StaffName);
     string token, time = DateTime.Now.AddMinutes(usercontext.Expiration).ToString();
     string ipAddress = Helper.GetIPAddress(context);
     string guid = Guid.NewGuid().ToString();
     SetUserContext(usercontext, context);
     //User token
     token = ipAddress + "~" + time + "~" + usercontext.StaffId + "~" + guid + "~" + usercontext.StaffNo;
     return Protect(token) + "|" + strPassword + "|" + IV + "|" + saltstr; //User token encryption
 }
 public string Protect(string stringtxt)
 {
     var outputData = Helper.ObjectToBase64(stringtxt);
     var textToOutPut = Encoding.UTF8.GetBytes(outputData);
     return Convert.ToBase64String(_protector.Protect(textToOutPut));
 }
// Set cookie
public void SetUserContext(UserContextModel userContext, HttpContext context)
 {
     if (context.Request.Cookies[SecurityConstant.AuthContext] != null)
     {
         context.Response.Cookies.Delete(SecurityConstant.AuthContext);
     }
     CookieOptions option = new CookieOptions()
     {
         HttpOnly = true,
         SameSite = SameSiteMode.Strict,
         Secure= userContext.IsHttps
     };
     var outputData = Helper.ObjectToBase64(userContext);
     var textToOutPut = Encoding.UTF8.GetBytes(outputData);
     var protectedPayload = Convert.ToBase64String(_protector.Protect(textToOutPut));
     context.Response.Cookies.Append(SecurityConstant.AuthContext, protectedPayload, option);
 }
