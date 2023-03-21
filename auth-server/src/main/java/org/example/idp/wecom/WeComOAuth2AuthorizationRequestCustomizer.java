package org.example.idp.wecom;

import org.example.config.properties.IDPWeComProperties;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 企业微信idp定制认证接口.
 *
 * @author zhouqiang
 * @since 2022/5/13
 */
public class WeComOAuth2AuthorizationRequestCustomizer {

	IDPWeComProperties idpWeComProperties = new IDPWeComProperties();

	private static final String IDP_REGISTRATION_ID = "wecom-idp";

	/**
	 * 企业微信的client_id 名称，等同client_id
	 */
	private static final String APP_ID = "appid";
	private static final String AGENT_ID = "agentid";

	private final String registrationId;

	public WeComOAuth2AuthorizationRequestCustomizer(String registrationId) {
		Assert.notNull(registrationId, IDP_REGISTRATION_ID + " registrationId flag must not be null");
		this.registrationId = registrationId;
	}

	public void customize(OAuth2AuthorizationRequest.Builder builder) {
		builder.attributes(attributes -> {
			String weComRegistrationId = (String) attributes.get(OAuth2ParameterNames.REGISTRATION_ID);
			if (registrationId.equals(weComRegistrationId)) {
				builder.parameters(this::weComParametersConsumer);
			}
		});
	}


	private void weComParametersConsumer(Map<String, Object> parameters) {
		//   client_id replace into appid here
		LinkedHashMap<String, Object> linkedParameters = new LinkedHashMap<>();
		//todo 从yml获取
		idpWeComProperties.setAgentId("1000015");
		//  k v  must be ordered
		parameters.forEach((k, v) -> {
			if (OAuth2ParameterNames.CLIENT_ID.equals(k)) {
				linkedParameters.put(APP_ID, v);
				linkedParameters.put(AGENT_ID, idpWeComProperties.getAgentId());
			} else {
				linkedParameters.put(k, v);
			}
		});
		parameters.clear();
		parameters.putAll(linkedParameters);
	}

}
