package com.appviewx.auth.radius;

import java.net.InetAddress;

public class RadiusRequestData {

	private InetAddress hostAddress;

	private String sharedSecret;

	private int authport;

	private int acctport;

	private int timeOut;

	private String vendorId;

	private String vendorType;

	private String userName;

	private String userPass;

	private String authMethod;

	public final InetAddress getHostAddress() {
		return hostAddress;
	}

	public final void setHostAddress(InetAddress hostAddress) {
		this.hostAddress = hostAddress;
	}

	public final String getSharedSecret() {
		return sharedSecret;
	}

	public final void setSharedSecret(String sharedSecret) {
		this.sharedSecret = sharedSecret;
	}

	public final int getAuthport() {
		return authport;
	}

	public final void setAuthport(int authport) {
		this.authport = authport;
	}

	public final int getAcctport() {
		return acctport;
	}

	public final void setAcctport(int acctport) {
		this.acctport = acctport;
	}

	public final int getTimeOut() {
		return timeOut;
	}

	public final void setTimeOut(int timeOut) {
		this.timeOut = timeOut;
	}

	public final String getVendorId() {
		return vendorId;
	}

	public final void setVendorId(String vendorId) {
		this.vendorId = vendorId;
	}

	public final String getVendorType() {
		return vendorType;
	}

	public final void setVendorType(String vendorType) {
		this.vendorType = vendorType;
	}

	public final String getUserName() {
		return userName;
	}

	public final void setUserName(String userName) {
		this.userName = userName;
	}

	public final String getUserPass() {
		return userPass;
	}

	public final void setUserPass(String userPass) {
		this.userPass = userPass;
	}

	public final String getAuthMethod() {
		return authMethod;
	}

	public final void setAuthMethod(String authMethod) {
		this.authMethod = authMethod;
	}
}
