package org.example.idp.wecom;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.json.GsonHttpMessageConverter;
import org.springframework.http.converter.json.JsonbHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Collections;


/**
 * 获取企业微信用户信息
 *
 * @author felord.cn
 * @since 2021 /8/12 17:45
 */
public class WeComOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

	private static final ParameterizedTypeReference<WeComOAuthUser> OAUTH2_USER_OBJECT
			= new ParameterizedTypeReference<>() {
	};
	private final RestOperations restOperations;

	/**
	 * Instantiates a new Wechat o auth 2 user service.
	 */
	public WeComOAuth2UserService() {
		RestTemplate restTemplate = new RestTemplate(
				Collections.singletonList(new WeComOAuth2UserHttpMessageConverter()));
		restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
		this.restOperations = restTemplate;
	}

	@Override
	public WeComOAuthUser loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		Assert.notNull(userRequest, "userRequest cannot be null");
		return getResponse(userRequest).getBody();
	}

	/**
	 * 获取企业微信用户信息借鉴{@link OAuth2AccessTokenResponseClient}
	 *
	 * @param userRequest the user request
	 * @return response
	 */
	private ResponseEntity<WeComOAuthUser> getResponse(OAuth2UserRequest userRequest) {
		String userInfoUri = userRequest.getClientRegistration()
				.getProviderDetails()
				.getUserInfoEndpoint()
				.getUri();
		try {
			LinkedMultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();
			queryParams.add(OAuth2ParameterNames.ACCESS_TOKEN, userRequest.getAccessToken().getTokenValue());
			String code = (String) userRequest.getAdditionalParameters().get(OAuth2ParameterNames.CODE);
			queryParams.add(OAuth2ParameterNames.CODE, code);
			URI userInfoEndpoint = UriComponentsBuilder.fromUriString(userInfoUri).queryParams(queryParams).build().toUri();
			return this.restOperations.exchange(userInfoEndpoint, HttpMethod.GET, null, OAUTH2_USER_OBJECT);
		} catch (OAuth2AuthorizationException ex) {
			OAuth2Error oauth2Error = ex.getError();
			StringBuilder errorDetails;
			errorDetails = new StringBuilder();
			errorDetails.append("Error details: [");
			errorDetails.append("UserInfo Uri: ")
					.append(userInfoUri);
			errorDetails.append(", Error Code: ").append(oauth2Error.getErrorCode());
			if (oauth2Error.getDescription() != null) {
				errorDetails.append(", Error Description: ").append(oauth2Error.getDescription());
			}
			errorDetails.append("]");
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
		}
	}


	private static class WeComOAuth2UserHttpMessageConverter
			extends AbstractHttpMessageConverter<WeComOAuthUser> {

		private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

		private final GenericHttpMessageConverter<Object> jsonMessageConverter = HttpMessageConverters.getJsonMessageConverter();

		public WeComOAuth2UserHttpMessageConverter() {
			super(DEFAULT_CHARSET, MediaType.TEXT_PLAIN,
					MediaType.APPLICATION_JSON,
					new MediaType("application", "*+json"));
		}

		@Override
		protected boolean supports(Class<?> clazz) {
			return WeComOAuthUser.class.isAssignableFrom(clazz);
		}

		@Override
		protected WeComOAuthUser
		readInternal(Class<? extends WeComOAuthUser> clazz, HttpInputMessage inputMessage)
				throws HttpMessageNotReadableException {
			try {
				// gh-6463: Parse parameter values as Object in order to handle potential JSON
				// Object and then convert values to String
				return (WeComOAuthUser) this.jsonMessageConverter
						.read(OAUTH2_USER_OBJECT.getType(), null, inputMessage);

			} catch (Exception ex) {
				throw new HttpMessageNotReadableException(
						"An error occurred reading the OAuth 2.0 Access Token Response: " + ex.getMessage(), ex,
						inputMessage);
			}
		}

		@Override
		protected void writeInternal(WeComOAuthUser tokenResponse, HttpOutputMessage outputMessage)
				throws HttpMessageNotWritableException {
			// noop
		}

		static class HttpMessageConverters {

			private static final boolean jackson2Present;

			private static final boolean gsonPresent;

			private static final boolean jsonbPresent;

			static {
				ClassLoader classLoader = HttpMessageConverters.class.getClassLoader();
				jackson2Present = ClassUtils.isPresent("com.fasterxml.jackson.databind.ObjectMapper", classLoader)
						&& ClassUtils.isPresent("com.fasterxml.jackson.core.JsonGenerator", classLoader);
				gsonPresent = ClassUtils.isPresent("com.google.gson.Gson", classLoader);
				jsonbPresent = ClassUtils.isPresent("javax.json.bind.Jsonb", classLoader);
			}

			private HttpMessageConverters() {
			}

			static GenericHttpMessageConverter<Object> getJsonMessageConverter() {
				if (jackson2Present) {
					return new MappingJackson2HttpMessageConverter();
				}
				if (gsonPresent) {
					return new GsonHttpMessageConverter();
				}
				if (jsonbPresent) {
					return new JsonbHttpMessageConverter();
				}
				return null;
			}
		}
	}
}
