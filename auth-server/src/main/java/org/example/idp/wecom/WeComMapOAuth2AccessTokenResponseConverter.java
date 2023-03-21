package org.example.idp.wecom;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.DefaultMapOAuth2AccessTokenResponseConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;

import java.util.Map;

/**
 * .
 *
 * @author zhouqiang
 * @since 2022/5/13
 */
public class WeComMapOAuth2AccessTokenResponseConverter
		implements Converter<Map<String, Object>, OAuth2AccessTokenResponse> {

	private final Converter<Map<String, Object>, OAuth2AccessTokenResponse>
			delegate = new DefaultMapOAuth2AccessTokenResponseConverter();

	/**
	 * 企业微信回调到 {baseUrl}/oauth/code/{registrationId}地址的code
	 * 由于企业微信的用户接口 /getuserinfo 需要code和access_token，所以在此处存储code
	 */
	private final String code;

	public WeComMapOAuth2AccessTokenResponseConverter(String code) {
		Assert.notNull(code, "code cannot be null");
		this.code = code;
	}

	@Override
	public OAuth2AccessTokenResponse convert(Map<String, Object> tokenResponseParameters) {
		// 避免 token_type 空校验异常
		tokenResponseParameters.put(OAuth2ParameterNames.TOKEN_TYPE, OAuth2AccessToken.TokenType.BEARER.getValue());
		tokenResponseParameters.put(OAuth2ParameterNames.CODE, code);
		return this.delegate.convert(tokenResponseParameters);
	}

}
