package com.appviewx.auth.radius;

import java.util.Set;

public class RadiusResponseData {

	private boolean isAuthenticated;

	private Set<String> roles;

	public final boolean isAuthenticated() {
		return isAuthenticated;
	}

	public final void setAuthenticated(boolean isAuthenticated) {
		this.isAuthenticated = isAuthenticated;
	}

	public final Set<String> getRoles() {
		return roles;
	}

	public final void setRoles(Set<String> roles) {
		this.roles = roles;
	}

}
