package com.appviewx.auth.radius;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import net.jradius.client.RadiusClient;
import net.jradius.client.auth.CHAPAuthenticator;
import net.jradius.client.auth.EAPMD5Authenticator;
import net.jradius.client.auth.MSCHAPv2Authenticator;
import net.jradius.client.auth.PAPAuthenticator;
import net.jradius.client.auth.RadiusAuthenticator;
import net.jradius.dictionary.Attr_NASPort;
import net.jradius.dictionary.Attr_NASPortType;
import net.jradius.dictionary.Attr_UserName;
import net.jradius.dictionary.Attr_UserPassword;
import net.jradius.exception.RadiusException;
import net.jradius.packet.AccessAccept;
import net.jradius.packet.AccessRequest;
import net.jradius.packet.RadiusRequest;
import net.jradius.packet.RadiusResponse;
import net.jradius.packet.attribute.AttributeFactory;
import net.jradius.packet.attribute.AttributeList;
import net.jradius.packet.attribute.VSAttribute;
import net.jradius.packet.attribute.value.AttributeValue;

/**
 * 
 * @author mageshwaran.p
 *
 */
@Component
public class RadiusAuthProcessor {

	private static final Logger LOGGER = LoggerFactory.getLogger(RadiusAuthProcessor.class);
	
	/**
	 * Constant for number One.
	 */
	private static final int ONE = 1;

	
	public RadiusResponseData authenticate(RadiusRequestData requestData) throws NoSuchAlgorithmException, IOException, RadiusException {
		
		RadiusResponseData radiusResponseData = new RadiusResponseData();
		
		final RadiusResponse accessresponse = doAuthenticate(requestData);
		
		 boolean isAuthenticated = accessresponse instanceof AccessAccept;
		
		radiusResponseData.setAuthenticated(isAuthenticated);
		if (isAuthenticated) {
			final String vendorKey = new StringBuilder().append(requestData.getVendorId()).append("-").append(requestData.getVendorType()).toString();
			
			Set<String> roles = getRoles(accessresponse, vendorKey);
			
			radiusResponseData.setRoles(roles);
		} else {
			LOGGER.info("Radius User {} login not authenticated", requestData.getUserName());
			radiusResponseData.setRoles(new HashSet<>());
		}
		return radiusResponseData;
	}
	/**
	 * This method performs authentication for given radius server config.
	 * 
	 * @param rc
	 *            the radiusclient
	 * @param userName
	 *            the userName
	 * @param userPass
	 *            the password
	 * @param authMethod
	 *            the authMethod
	 * @return RadiusResponse
	 * @throws RadiusException
	 * @throws NoSuchAlgorithmException
	 */
	private RadiusResponse doAuthenticate(RadiusRequestData radiusRequest)
			throws IOException, NoSuchAlgorithmException, RadiusException {
		
		RadiusClient rc = getRadiusClient(radiusRequest);
		
		AttributeFactory.loadAttributeDictionary("net.jradius.dictionary.AttributeDictionaryImpl");
		final AttributeList attrs = new AttributeList();
		attrs.add(new Attr_UserName(radiusRequest.getUserName()));
		attrs.add(new Attr_NASPortType(Attr_NASPortType.Wireless80211));
		attrs.add(new Attr_NASPort(ONE));
		final RadiusRequest request = new AccessRequest(rc, attrs);
		request.addAttribute(new Attr_UserPassword(radiusRequest.getUserPass()));
		RadiusAuthenticator authenticator;
		switch (radiusRequest.getAuthMethod().toLowerCase()) {
		case "chap":
			authenticator = new CHAPAuthenticator();
			break;
		case "mschapv2":
			authenticator = new MSCHAPv2Authenticator();
			break;
		case "eapmd5":
			authenticator = new EAPMD5Authenticator();
			break;
		case "pap":
		default:
			authenticator = new PAPAuthenticator();
		}
		return rc.authenticate((AccessRequest) request, authenticator, 0);
	}

	private Set<String> getRoles(RadiusResponse response, String vendorKey) {

		Set<String> roles = new HashSet<>();

		try {
			final AttributeList attributes = response.getAttributes();
			final List<Object> responseValues = new ArrayList<>(attributes.getMap().values());

			for (Object responseObject : responseValues) {

				if (!(responseObject instanceof VSAttribute)) {
					continue;
				}

				final VSAttribute vsAttribute = (VSAttribute) responseObject;
				final long vendorId = vsAttribute.getVendorId();
				final long vendorType = vsAttribute.getVsaAttributeType();
				final String aDkey = vendorId + "-" + vendorType;
				/**
				 * @author indhumathi.v
				 *
				 */
				final AttributeValue attributeValue = vsAttribute.getValue();
				final String roleName = new String(attributeValue.getBytes(), "UTF-8");

				if (vendorKey.equals(aDkey)) {
					if (roleName.contains(",")) {
						roles.addAll((Arrays.asList(StringUtils.stripAll(roleName.split(",")))));
					} else {
						roles.add(StringUtils.trim(roleName));
					}
					return roles;
				}
			}
		} catch (Exception e) {
			LOGGER.error("Error while parsing the Radius response {}", response, e);
		}
		return roles;
	}

	private RadiusClient getRadiusClient(RadiusRequestData radiusRequest) throws IOException {
		
		RadiusClient radiusClient = new RadiusClient(radiusRequest.getHostAddress(), radiusRequest.getSharedSecret(),
				radiusRequest.getAuthport(), radiusRequest.getAcctport(), radiusRequest.getTimeOut());
		LOGGER.info("RadiusClient has been generated for IP : {}", radiusRequest.getHostAddress());
		return radiusClient;
	}

}
