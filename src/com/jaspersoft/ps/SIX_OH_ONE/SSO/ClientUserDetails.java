package com.jaspersoft.ps.SIX_OH_ONE.SSO;


import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.*;

import com.jaspersoft.jasperserver.api.metadata.user.domain.Role;
import com.jaspersoft.jasperserver.api.metadata.user.domain.User;
import com.jaspersoft.jasperserver.multipleTenancy.MTUserDetails;

/**
 * @author jhuber@tibco.com, 2015
 * @version 6.0.1.1
 */
public class ClientUserDetails implements MTUserDetails, User, Serializable {

	private static Log log = LogFactory.getLog(ClientUserDetails.class);

	private final String username;
	private final String email;
	private final String full_name;
	
	private final String[][] profileAttributes;
	private final List<TenantInfo> tenants;
	Collection<? extends GrantedAuthority> authorities;

	private final boolean enabled = true;
	private final boolean externallyDefined = true;

	private static final long serialVersionUID = 4287079258663733766L;

	public ClientUserDetails(String username, String email, String full_name, List<TenantInfo> tenants, GrantedAuthority[] authorities, String[][] profileAttributes) {
		this.username = username;
		this.email = email;
		this.full_name = full_name;
		this.profileAttributes = profileAttributes;
		this.tenants = tenants;
		this.authorities = getAuthorities();
	}

	
	@Override
	public String getUsername() {
		return username;
	}

	@Override
	public String getPassword() {
		return null;
	}
	
	public String[][] getProfileAttributes() {
		return profileAttributes;
	}

	@Override
	public boolean isEnabled() {
		return enabled;
	}

	public boolean isExternallyDefined() {
		return externallyDefined;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public List<TenantInfo> getTenantPath() {
		return tenants;
	}


	@Override
	public String getTenantId() {
		// TODO Auto-generated method stub
		return null;
	}


	@Override
	public void setTenantId(String arg0) {
		// TODO Auto-generated method stub
		
	}


	@Override
	public void addRole(Role arg0) {
		// TODO Auto-generated method stub
		
	}


	@Override
	public List getAttributes() {
		// TODO Auto-generated method stub
		return null;
	}


	@Override
	public String getEmailAddress() {
		return email;
	}


	@Override
	public String getFullName() {
		return full_name;
	}


	@Override
	public Date getPreviousPasswordChangeTime() {
		// TODO Auto-generated method stub
		return null;
	}


	@Override
	public Set getRoles() {
		// TODO Auto-generated method stub
		return null;
	}


	@Override
	public void removeRole(Role arg0) {
		// TODO Auto-generated method stub
		
	}


	@Override
	public void setAttributes(List arg0) {
		// TODO Auto-generated method stub
		
	}


	@Override
	public void setEmailAddress(String arg0) {
		// TODO Auto-generated method stub
		
	}


	@Override
	public void setEnabled(boolean arg0) {
		// TODO Auto-generated method stub
		
	}


	@Override
	public void setExternallyDefined(boolean arg0) {
		// TODO Auto-generated method stub
		
	}


	@Override
	public void setFullName(String arg0) {
		// TODO Auto-generated method stub
		
	}


	@Override
	public void setPassword(String arg0) {
		// TODO Auto-generated method stub
		
	}


	@Override
	public void setPreviousPasswordChangeTime(Date arg0) {
		// TODO Auto-generated method stub
		
	}


	@Override
	public void setRoles(Set arg0) {
		// TODO Auto-generated method stub
		
	}


	@Override
	public void setUsername(String arg0) {
		// TODO Auto-generated method stub
	}
}
