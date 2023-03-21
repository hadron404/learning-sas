package org.example.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * 企业微信认证定制属性.
 *
 * @author zhouqiang
 * @since 2022/5/13
 */
@Configuration
@ConfigurationProperties(prefix = "wecom")
public class IDPWeComProperties {

	private String agentId;

	public String getAgentId() {
		return agentId;
	}

	public void setAgentId(String agentId) {
		this.agentId = agentId;
	}
}
