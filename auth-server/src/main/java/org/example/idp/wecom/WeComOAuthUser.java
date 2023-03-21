package org.example.idp.wecom;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * .
 *
 * @author zhouqiang
 * @since 2022/5/13
 */

public class WeComOAuthUser implements OAuth2User {
	private Set<GrantedAuthority> authorities;

	@JsonProperty(value = "UserId")
	private String userId;

	@Override
	public Map<String, Object> getAttributes() {
		return Collections.emptyMap();
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public String getName() {
		return this.userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public void setAuthorities(Set<GrantedAuthority> authorities) {
		this.authorities = authorities;
	}
}
