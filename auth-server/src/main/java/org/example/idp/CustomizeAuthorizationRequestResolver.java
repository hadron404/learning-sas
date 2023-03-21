package org.example.idp;

import org.example.idp.wecom.WeComOAuth2AuthorizationRequestCustomizer;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;

/**
 * .
 *
 * @author zhouqiang
 * @since 2022/5/13
 */
public class CustomizeAuthorizationRequestResolver {
    /**
     * @param clientRegistrationRepository the client registration repository
     * @return DefaultOAuth2AuthorizationRequestResolver
     */
    public static OAuth2AuthorizationRequestResolver
    weComRequestResolver(ClientRegistrationRepository clientRegistrationRepository) {
        DefaultOAuth2AuthorizationRequestResolver resolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository,
                        OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
        resolver.setAuthorizationRequestCustomizer(
                new WeComOAuth2AuthorizationRequestCustomizer(IdpConstants.REGISTRATION_ID_WECOM)::customize);
        return resolver;
    }
}
