package org.example.idp;

import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * .
 *
 * @author zhouqiang
 * @since 2022/5/13
 */
public class CustomizeRequestEntity {
	public static MultiValueMap<String, String> buildWeComRequestEntity(OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest) {
		// 获取微信的客户端配置
		ClientRegistration clientRegistration = authorizationCodeGrantRequest.getClientRegistration();
		OAuth2AuthorizationExchange authorizationExchange = authorizationCodeGrantRequest.getAuthorizationExchange();
		MultiValueMap<String, String> formParameters = new LinkedMultiValueMap<>();
		// grant_type
		formParameters.add(OAuth2ParameterNames.GRANT_TYPE, authorizationCodeGrantRequest.getGrantType().getValue());
		// code
		formParameters.add(OAuth2ParameterNames.CODE, authorizationExchange.getAuthorizationResponse().getCode());
		// 如果有redirect-uri
		String redirectUri = authorizationExchange.getAuthorizationRequest().getRedirectUri();
		if (redirectUri != null) {
			formParameters.add(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
		}
		formParameters.add("corpid", clientRegistration.getClientId());
		formParameters.add("corpsecret", clientRegistration.getClientSecret());
		return formParameters;
	}
}
