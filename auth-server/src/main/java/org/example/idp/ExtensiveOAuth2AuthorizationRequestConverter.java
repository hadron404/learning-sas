package org.example.idp;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

/**
 * 企业微信获取token自定义.
 *
 * @author zhouqiang
 * @since 2022/5/13
 */
public class ExtensiveOAuth2AuthorizationRequestConverter implements Converter<OAuth2AuthorizationCodeGrantRequest, RequestEntity<?>> {
	private static final HttpHeaders DEFAULT_TOKEN_REQUEST_HEADERS = getDefaultTokenRequestHeaders();
	private final Converter<OAuth2AuthorizationCodeGrantRequest, RequestEntity<?>> defaultConverter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();

	@Override
	public RequestEntity<?> convert(OAuth2AuthorizationCodeGrantRequest source) {
		ClientRegistration clientRegistration = source.getClientRegistration();
		HttpHeaders headers = getTokenRequestHeaders(clientRegistration);

		String tokenUri = clientRegistration.getProviderDetails().getTokenUri();
		// 针对企业微信的定制
		if (IdpConstants.REGISTRATION_ID_WECOM.equals(clientRegistration.getRegistrationId())) {
			MultiValueMap<String, String> queryParameters = CustomizeRequestEntity.buildWeComRequestEntity(source);
			URI uri = UriComponentsBuilder.fromUriString(tokenUri).queryParams(queryParameters).build().toUri();
			return RequestEntity.get(uri).headers(headers).build();
		}
		return defaultConverter.convert(source);
	}

	private static HttpHeaders getDefaultTokenRequestHeaders() {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
		final MediaType contentType = MediaType.valueOf(MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8");
		headers.setContentType(contentType);
		return headers;
	}

	static HttpHeaders getTokenRequestHeaders(ClientRegistration clientRegistration) {
		HttpHeaders headers = new HttpHeaders();
		headers.addAll(DEFAULT_TOKEN_REQUEST_HEADERS);
		if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(clientRegistration.getClientAuthenticationMethod())) {
			String clientId = encodeClientCredential(clientRegistration.getClientId());
			String clientSecret = encodeClientCredential(clientRegistration.getClientSecret());
			headers.setBasicAuth(clientId, clientSecret);
		}
		return headers;
	}

	private static String encodeClientCredential(String clientCredential) {
		try {
			return URLEncoder.encode(clientCredential, StandardCharsets.UTF_8.toString());
		} catch (UnsupportedEncodingException ex) {
			// Will not happen since UTF-8 is a standard charset
			throw new IllegalArgumentException(ex);
		}
	}

}
