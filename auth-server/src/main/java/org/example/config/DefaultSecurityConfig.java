/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.example.config;

import org.example.idp.CustomizeAuthorizationRequestResolver;
import org.example.idp.DelegatingOAuth2UserService;
import org.example.idp.IdpConstants;
import org.example.idp.wecom.WeComAuthorizationCodeTokenResponseClient;
import org.example.idp.wecom.WeComOAuth2UserService;
import org.example.security.FederatedIdentityConfigurer;
import org.example.security.UserRepositoryOAuth2UserHandler;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collections;

/**
 * @author Steve Riesenberg
 * @since 0.2.3
 */
@EnableWebSecurity
public class DefaultSecurityConfig {

	// @formatter:off
	@Bean
	public SecurityFilterChain
	defaultSecurityFilterChain(HttpSecurity http)
			throws Exception {
		FederatedIdentityConfigurer federatedIdentityConfigurer = new FederatedIdentityConfigurer()
				.oauth2UserHandler(new UserRepositoryOAuth2UserHandler());
		http
				.authorizeHttpRequests(authorizeRequests ->
						authorizeRequests
								.requestMatchers("/assets/**", "/webjars/**", "/login").permitAll()
								.anyRequest().authenticated()
				)
				.formLogin(Customizer.withDefaults())
				.apply(federatedIdentityConfigurer);
		applyCustomize(http);
		return http.build();
	}

	// @formatter:on
	private void applyCustomize(HttpSecurity http) throws Exception {
		ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
		ClientRegistrationRepository clientRegistrationRepository =
				applicationContext.getBean(ClientRegistrationRepository.class);
		OAuth2AuthorizationRequestResolver weComAuthorizationRequestResolver =
				CustomizeAuthorizationRequestResolver.weComRequestResolver(clientRegistrationRepository);
		OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> weComAccessTokenResponseClient =
				new WeComAuthorizationCodeTokenResponseClient();
		OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = getDelegatingOauth2UserService();
		http.oauth2Login((oauth2Login) ->
				oauth2Login
						//自定义认证端点配置
						.authorizationEndpoint((authorizationEndpoint) ->
								authorizationEndpoint.authorizationRequestResolver(weComAuthorizationRequestResolver))
						//自定义token端点配置
						.tokenEndpoint((tokenEndpoint) ->
								tokenEndpoint.accessTokenResponseClient(weComAccessTokenResponseClient))
						//自定义用户信息端点配置
						.userInfoEndpoint((userInfoEndpoint) -> userInfoEndpoint.userService(oAuth2UserService))
		);
		http.oauth2Client((oauth2Client) -> oauth2Client.authorizationCodeGrant()
				.authorizationRequestResolver(weComAuthorizationRequestResolver)
				.accessTokenResponseClient(weComAccessTokenResponseClient));
	}

	private OAuth2UserService<OAuth2UserRequest, OAuth2User> getDelegatingOauth2UserService() {
		return new DelegatingOAuth2UserService<>(
				Collections.singletonMap(IdpConstants.REGISTRATION_ID_WECOM, new WeComOAuth2UserService()));
	}

	// @formatter:off
	@Bean
	public UserDetailsService users() {
		UserDetails user = User.withDefaultPasswordEncoder()
				.username("user1")
				.password("password")
				.roles("USER")
				.build();
		return new InMemoryUserDetailsManager(user);
	}
	// @formatter:on

}
