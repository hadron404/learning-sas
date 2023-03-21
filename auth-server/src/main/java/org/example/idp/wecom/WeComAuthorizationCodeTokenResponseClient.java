package org.example.idp.wecom;

import org.example.idp.ExtensiveOAuth2AuthorizationRequestConverter;
import org.example.idp.IdpConstants;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Arrays;

/**
 * 企业微信 responseClient 扩展.
 *
 * @author zhouqiang
 * @since 2022/5/13
 */
public class WeComAuthorizationCodeTokenResponseClient
		implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {

	private final DefaultAuthorizationCodeTokenResponseClient defaultClient
			= new DefaultAuthorizationCodeTokenResponseClient();

	private final ExtensiveOAuth2AuthorizationRequestConverter requestEntityConverter
			= new ExtensiveOAuth2AuthorizationRequestConverter();

	public WeComAuthorizationCodeTokenResponseClient() {
		defaultClient.setRequestEntityConverter(requestEntityConverter);
	}

	@Override
	public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
		ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();
		if (IdpConstants.REGISTRATION_ID_WECOM.equals(clientRegistration.getRegistrationId())) {
			RequestEntity<?> request = this.requestEntityConverter.convert(authorizationGrantRequest);
			Assert.notNull(request, "request cannot be null");
			UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(String.valueOf(request.getUrl())).build();
			MultiValueMap<String, String> queryParams = uriComponents.getQueryParams();
			defaultClient.setRestOperations(weComRestTemplate(queryParams.get(OAuth2ParameterNames.CODE).get(0)));
		}
		return defaultClient.getTokenResponse(authorizationGrantRequest);
	}

	private RestTemplate weComRestTemplate(String code) {
		OAuth2AccessTokenResponseHttpMessageConverter tokenResponseHttpMessageConverter
				= new OAuth2AccessTokenResponseHttpMessageConverter();
		// 微信返回的content-type 是 text-plain
		tokenResponseHttpMessageConverter.setSupportedMediaTypes(Arrays.asList(MediaType.APPLICATION_JSON,
				MediaType.TEXT_PLAIN,
				new MediaType("application", "*+json")));
		WeComMapOAuth2AccessTokenResponseConverter weComResponseConverter =
				new WeComMapOAuth2AccessTokenResponseConverter(code);
		// 兼容微信解析
		tokenResponseHttpMessageConverter.setAccessTokenResponseConverter(weComResponseConverter);
		RestTemplate restTemplate = new RestTemplate(
				Arrays.asList(new FormHttpMessageConverter(),
						tokenResponseHttpMessageConverter
				));
		restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
		return restTemplate;
	}

}
