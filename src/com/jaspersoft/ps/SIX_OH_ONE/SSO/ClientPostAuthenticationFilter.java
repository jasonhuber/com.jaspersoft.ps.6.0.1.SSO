package com.jaspersoft.ps.SIX_OH_ONE.SSO;



import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

import com.jaspersoft.jasperserver.api.metadata.common.domain.Folder;
import com.jaspersoft.jasperserver.api.metadata.common.service.RepositoryService;
import com.jaspersoft.jasperserver.api.metadata.user.domain.ProfileAttribute;
import com.jaspersoft.jasperserver.api.metadata.user.domain.User;
import com.jaspersoft.jasperserver.api.metadata.user.domain.impl.client.MetadataUserDetails;
import com.jaspersoft.jasperserver.api.metadata.user.service.ObjectPermissionService;
import com.jaspersoft.jasperserver.api.metadata.user.service.ProfileAttributeCategory;
import com.jaspersoft.jasperserver.api.metadata.user.service.ProfileAttributeService;
import com.jaspersoft.jasperserver.api.metadata.user.service.UserAuthorityService;
import com.jaspersoft.jasperserver.api.metadata.user.service.impl.ExternalUserService;

/**
 * @author jhuber@tibco.com, 2015
 * @version 6.0.1.1
 */

public class ClientPostAuthenticationFilter implements InitializingBean, Filter {

	private static Log log = LogFactory.getLog(ClientPostAuthenticationFilter.class);

	private ProfileAttributeService profileAttributeService;


	/**
	 * this filter will be executed after the JIAuthenticationSynchronizer, so
	 * we have a new user details object in the session and can also use the
	 * persisted user object to store profile attributes on it. This filter gets
	 * only executed if the clientAuth parameter is found in the request.
	 */
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

		// only activate if this is a client authentication
		Object clientAuth = request.getAttribute("clientAuth");
		if ((clientAuth == null) || !"true".equals(clientAuth)) {
			HttpSession session = ((HttpServletRequest) request).getSession();
			  //process only if this is a client authentication
			   clientAuth = session.getAttribute("clientAuth");
			   if ((clientAuth == null) || !"true".equals(clientAuth)) 
				   {
					   chain.doFilter(request, response);
						return;
				   }
			}

		// get the authentication object from the security context
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();

		// the authentication synchronizer creates a new MetadataUserDetails
		// object which holds all user information
		MetadataUserDetails user = (MetadataUserDetails) auth.getPrincipal();
		
        // the original user details can be retrieved
		ClientUserDetails clientDetails = (ClientUserDetails) user.getOriginalAuthentication().getPrincipal();

		// this should never happen
		if (clientDetails == null) {
			if (log.isWarnEnabled()) {
				log.warn("client auth header token is found, but no client userdetails");
			}
			chain.doFilter(request, response);
			return;
		}
		
		String[][] profileAttributes = clientDetails.getProfileAttributes();
		
		for (int i= 0; i < profileAttributes.length; i++) {
			//save profile attribute to database
			//profileAttributeService.setCurrentUserPreferenceValue(profileAttributes[i][0], profileAttributes[i][1]);
			ProfileAttribute myAttr = profileAttributeService.newProfileAttribute(null);
			myAttr.setPrincipal(user);
			myAttr.setAttrName(profileAttributes[i][0]);
			myAttr.setAttrValue(profileAttributes[i][1]);
			myAttr.setCategory(ProfileAttributeCategory.TENANT);
			try
			{
			profileAttributeService.putProfileAttribute(null, myAttr);
			}
			catch (Exception e)
			{
				System.out.println(e.toString());	
			}
		}
		user.setAttributes(profileAttributeService.getCurrentUserProfileAttributes(ProfileAttributeCategory.TENANT));
		//proceed with other filters
		
		chain.doFilter(request, response);
	}

	

	// -- helper methods
	/**
	 * the bean properties need to be set.
	 */
	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(profileAttributeService);
		//Assert.notNull(profileAttrName);
	}

	/**
	 * nothing to do here
	 */
	public void destroy() {
	}

	/**
	 * nothing to do here
	 */
	public void init(FilterConfig arg0) throws ServletException {
	}

	// getter and setter methods for bean properties

	public ProfileAttributeService getProfileAttributeService() {
		return profileAttributeService;
	}

	public void setProfileAttributeService(ProfileAttributeService profileAttrService) {
		profileAttributeService = profileAttrService;
	}
}
