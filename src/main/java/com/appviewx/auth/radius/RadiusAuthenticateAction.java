package com.appviewx.auth.radius;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.ObjectMapper;

import net.jradius.exception.RadiusException;

/**
 * The Class RadiusAuthenticateAction.
 *
 * @author mageshwaran.p
 */
@RestController
public class RadiusAuthenticateAction {

	private static final Logger LOGGER = LoggerFactory.getLogger(RadiusAuthenticateAction.class);

	@Autowired
	private RadiusAuthProcessor authProcessor;

	@PostMapping("/radius-user-aaa")
	protected Map<String, Object> execute(@RequestBody Map<String, Object> payload) {

		Map<String, Object> response = new HashMap<>();
		try {
			Object body = payload.get("payload");
			ObjectMapper mapper = new ObjectMapper();
			RadiusRequestData requestData = mapper.convertValue(body, RadiusRequestData.class);

			RadiusResponseData resData = authProcessor.authenticate(requestData);
			response.put("response", resData);
			LOGGER.info("RadiusAuthenticateAction: Radius user authentication success: {}, {}",
					resData.isAuthenticated(), resData.getRoles());
			return response;
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("Error while radius user authentication: Algorithm negotiation fails. {}", e.getMessage());
		} catch (IOException e) {
			LOGGER.error("Error while radius user authentication: IOException. {}", e.getMessage());
		} catch (RadiusException e) {
			LOGGER.error("Error while radius user authentication: RadiusException. {}", e.getMessage());
		}
		RadiusResponseData responseData = new RadiusResponseData();
		responseData.setAuthenticated(false);
		responseData.setRoles(new HashSet<>());

		response.put("response", responseData);
		return response;
	}

}
