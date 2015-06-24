package com.jaspersoft.ps.SIX_OH_ONE.SSO;



import java.io.Serializable;

import com.jaspersoft.jasperserver.multipleTenancy.MTUserDetails.TenantInfo;
/**
 * @author jhuber@tibco.com, 2015
 * @version 6.0.1.1
 */

public class ClientTenantInfo implements TenantInfo, Serializable {

	private static final long serialVersionUID = 4357843572490382761L;

	private String id;
	private String label;
	private String description;

	public ClientTenantInfo(String id, String label, String description) {
		this.id = id;
		this.label = label;
		this.description = description;
	}

	@Override
	public String getId() {
		return id;
	}

	@Override
	public String getLabel() {
		return label;
	}

	@Override
	public String getDescription() {
		return description;
	}

}
