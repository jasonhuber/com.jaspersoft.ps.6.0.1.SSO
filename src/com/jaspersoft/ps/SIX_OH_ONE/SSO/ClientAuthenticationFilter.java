package com.jaspersoft.ps.SIX_OH_ONE.SSO;


import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.*;
import org.springframework.security.core.*;

import com.jaspersoft.jasperserver.multipleTenancy.MTUserDetails.TenantInfo;

/**
 * @author jhuber@tibco.com, 2015
 * @version 6.0.1.1
 */

public class ClientAuthenticationFilter implements InitializingBean,Filter {

	private static Log log = LogFactory.getLog(ClientAuthenticationFilter.class);
	
	public static boolean disable_ssl_verification;

	private String tokenRequestParameter;
	private String validTokenEndpoint;
	private String validTokenParameter;
	
	private String tokenSessionAttribute ="clientAuthToken";

	/**
	 * the filter chain is extended to filter each request with this custom
	 * filter. Once it is validated, that the request contains the required
	 * parameters, from these parameters user information are retrieved and set
	 * into a JasperReports Server user object which is set into the session.
	 * Further down the filterChain the JIAuthenticationSynchronizer persists
	 * these user details into the JasperReports Server database.
	 */
	
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

		// if no token is found proceed with other filters
		if (!isClientRequest(request)) {
			if (log.isDebugEnabled()) {
				log.debug("this is not a custom auth request, proceed with other filters");
			}
			chain.doFilter(request, response);
			return;
		}

		String token = getToken(request);
		if(token.isEmpty())
		{
			if (log.isDebugEnabled()) {
				log.debug("no token was passed!");
			}
			return;
		}
		// retrieve existing authentication
		Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();

		HttpServletRequest req = (HttpServletRequest) request;
		HttpSession session = req.getSession();
		String sessionToken = (String) session.getAttribute(tokenSessionAttribute);
		if (sessionToken != null && sessionToken.equals(token) && existingAuth != null && existingAuth.isAuthenticated()) {
			//already authenticated
			chain.doFilter(request, response);
			return;
		}

		// loads user information in JasperServer user object
		ClientUserDetails userDetails = getUserDetails(req);

		// now proceed with authentication
		if (userDetails == null) {
			if (log.isDebugEnabled()) {
				log.debug("user details could not be extracted, proceeding with other filters");
			}
			chain.doFilter(request, response);
			return;
		}


		// if an existing authentication is found
		if (existingAuth != null) {
			SecurityContextHolder.getContext().setAuthentication(null);
		}

		// to let the JIAuthenticationSynchronizer do his job, set a
		// authentication token in the session and assign the user details to it\
		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword());
		authRequest.setDetails(userDetails);
		// put this in the current session
		SecurityContextHolder.getContext().setAuthentication(authRequest);

		if (log.isDebugEnabled()) {
			log.debug("authentication object processed");
		}

		if (sessionToken == null || !sessionToken.equals(token)) {
			session.setAttribute(tokenSessionAttribute, token);
		}

		// as we have to post-process the profile attributes, and don't want to
		// fire re-writing the profile attributes with each single request we
		// add simply a flag which we will refer to later
		request.setAttribute("clientAuth", "true");
		
		// done, now let other filters do the rest of the job
		chain.doFilter(req, response);
	}

	// -- helper methods

	/**
	 * this method retrieves the user details from the URL. TODO Add here all
	 * functionality you might need to use to retrieve all user information
	 */
	@SuppressWarnings("deprecation")
	private ClientUserDetails getUserDetails(ServletRequest req) {

		log.info("begin token validation program");   

				String token = getToken(req);

				log.info("received token info : " + token);

				HttpURLConnection conn = null;

				//get user info for the user, including roles and attributes (this is using POST)

				String userInfoStr = null;

				 

				try {

				//String urlStr = validTokenEndpoint + "?" + validTokenParameter + "=" + token;
				//using the below since the endpoint is 
				//http://service-mas-futureqa.mc.wgenhq.net:50004/sessions/12345 if token is 12345

				String urlStr = validTokenEndpoint + token;

				log.info("constructed URL String : " + urlStr);

				URL url = new URL(urlStr);

				log.info("before Open connection : ");
				
				conn = (HttpURLConnection) url.openConnection();
				conn.setRequestMethod("GET");
				conn.setDoOutput(true); //this is for POST and PUT
				conn.setDoInput(true); //this is for GET
				conn.setUseCaches(false);
				conn.setAllowUserInteraction(false);
				
				log.info("before response check : ");
	
				String userpass = "USERNAME:PASSWORD";
				String basicAuth = "Basic " + javax.xml.bind.DatatypeConverter.printBase64Binary(userpass.getBytes());
				conn.setRequestProperty ("Authorization", basicAuth);
				
				
				if (conn.getResponseCode() != 200) {return null;}

				log.info("got the response back : " + conn.getResponseCode());

		
				//Get Response
				InputStream is = conn.getInputStream();

				userInfoStr = convertInputStream2String(is);
				//*** uncomment ending with this single line  

				log.info("got the userinfo: " + userInfoStr);
				//userInfoStr = "{\"org_id\": \"123\",\"org_name\": \"Orange, LLC\",\"auth_id\": 555,\"email\": \"cyber@orange.com\",\"full_name\": \"Ted Williams\",\"title\": \"CISO\",\"security_groups\":[1056],\"roles\": [\"Admin\",\"Report Viewer\"],\"custom_attributes\": {\"phone\": \"555-999-1010\",\"ClientID\": \"1053\"}}";
		
				} catch (Exception e) {

					log.error("Failed retrieving user info", e);

				} finally {

				if(conn != null) {

				conn.disconnect(); 

				}

				log.info("successfully completed?? <- this only means you made it past the disconnect.... JSON was:  " + userInfoStr + "<-- tell Jason this");

				}

		log.debug("Userinfo string was: " + userInfoStr);
		log.info("Starting to parse JSON");
		JSONObject json = new JSONObject();
		try
		{
			json = (JSONObject) JSONSerializer.toJSON(userInfoStr);	
		}
		catch(Exception e) {
			log.error("JSON Was invalid? Info Received: " + userInfoStr, e);
		} 
		
		log.info("JSON Parsed");
			//JSONObject userInfoObj = json.getJSONObject("userinfo");
			String 	org_id = "Organization";//json.getString("org_id");
			String org_name = "organization_1";//json.getString("org_name");
			String auth_id = json.getString("username");
			String email = json.getString("email");;
			String full_name = json.getString("first_name") + " " + json.getString("last_name") ;
			//JSONArray security_groups = json.getJSONArray("security_groups");
			//right now we do not have much in the way of roles.
			JSONArray myArray = new JSONArray();
			JSONObject j = new JSONObject();
			j.put("key","ROLE_USER");
			j.put("array",myArray);
			
			JSONArray roles =  myArray;
		
		//JSONObject custom_attributes = json.getJSONObject("custom_attributes");
		Iterator iter = json.keys();
		List<String[]> attributesAttr = new ArrayList<String[]>();
		
		
		while(iter.hasNext())
		{
			
			String key = (String) iter.next();
			if(key != "auth_token" && key != "session_nonce")
			{
				String value = json.getString(key);
				attributesAttr.add(new String[]{key, value});
			}
		}


		//roles
		GrantedAuthority[] authorities = new GrantedAuthority[roles.length()];
		Iterator roleIter = roles.iterator();
		for (int i = 0; i < authorities.length; i++) {
			authorities[i] = new GrantedAuthorityImpl((String) roleIter.next());
		}

		//profile attributes
		String[][] attributes = new String[attributesAttr.size()][2];
			Iterator attributesIter = attributesAttr.iterator();
		for (int i = 0; attributesIter.hasNext(); i++) {
			attributes[i] = (String[]) attributesIter.next();
		}

		//organizations
		List<TenantInfo> tenants = new ArrayList<TenantInfo>();
		ClientTenantInfo tenant = new ClientTenantInfo(org_name, org_id, null);
		tenants.add(tenant);
		
		log.info("Sending in the JSON (now objects) to create the UserDetails object.");
		ClientUserDetails userDetails = new ClientUserDetails(auth_id, email, full_name, tenants, authorities, attributes);
		return userDetails;

		
		
	}

	/**
	 * this is the validation if the request contains all information you need.
	 * Don't add too much functionality here as this is checked for all
	 * requests.
	 * 
	 * @param req
	 * @return <code>true</code> if enough information found, otherwise false.
	 */
	private boolean isClientRequest(ServletRequest req) {
		String aToken = req.getParameter(tokenRequestParameter);
		return (aToken != null) && !aToken.trim().equals("");
	}

	private String getToken(ServletRequest req) {
		String aToken = req.getParameter(tokenRequestParameter);
		if (aToken != null) {
			aToken = aToken.trim();
		}
		return aToken;
	}

	// -- helper methods
	/**
	 * the bean properties need to be set. if the role separator is not defined,
	 * it is by default ,
	 */
	@Override
	public void afterPropertiesSet() throws Exception {
		/*		Assert.notNull(paramUser);
		Assert.notNull(paramTenants);
		Assert.notNull(paramRoles);
		Assert.notNull(paramProfileAttrValue);
		if (separator == null) {
			separator = ",";
		}*/

	}

	/**
	 * nothing to do here
	 */
	public void destroy() {
	}


	@Override
	public void init(FilterConfig arg0) throws ServletException {
		// TODO Auto-generated method stub

	}

	
	private String getQuery(List<NameValuePair> params) throws UnsupportedEncodingException
	{
		StringBuilder result = new StringBuilder();
		boolean first = true;

		for (NameValuePair pair : params)
		{
			if (first)
				first = false;
			else
				result.append("&");

			result.append(URLEncoder.encode(pair.getName(), "UTF-8"));
			result.append("=");
			result.append(URLEncoder.encode(pair.getValue(), "UTF-8"));
		}

		return result.toString();
	}

	public String getTokenRequestParameter() {
		return tokenRequestParameter;
	}
	
	protected static String convertInputStream2String(InputStream is) throws IOException
	{
		StringWriter writer = new StringWriter();
		IOUtils.copy(is, writer, "UTF-8");
		return writer.toString().trim();
	}

	public void setTokenRequestParameter(String tokenRequestParameter) {
		this.tokenRequestParameter = tokenRequestParameter;
	}

	public String getValidTokenEndpoint() {
		return validTokenEndpoint;
	}

	public void setValidTokenEndpoint(String validTokenEndpoint) {
		this.validTokenEndpoint = validTokenEndpoint;
	}

	public String getValidTokenParameter() {
		return validTokenParameter;
	}

	public void setValidTokenParameter(String validTokenParameter) {
		this.validTokenParameter = validTokenParameter;
	}

	
}