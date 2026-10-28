/*
 * Copyright (c) 2018, hiwepy (https://github.com/easy-4-java).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.biz.property;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.Data;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * Security Authc Properties
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@Data
public class SecurityAuthcProperties {

	/** Authorization Path Pattern */
	private String pathPattern = "/login";
	
	/**
	 * 重定向地址：会话注销后的重定向地址
	 */
	private String redirectUrl = "/";
	/**
	 * 系统主页：登录成功后跳转路径
	 */
	private String successUrl = "/index";;
	/**
	 * 异常页面：认证失败时的跳转路径
	 */
	private String failureUrl = "/error";
	/**
	 * 未授权页面：无权限时的跳转路径
	 */
	private String accessDeniedUrl = "/errors/401";
	/**
	 * Indicates if the filter chain should be continued prior to delegation to
	 * {@link #successfulAuthentication(HttpServletRequest, HttpServletResponse, FilterChain, Authentication)}
	 * , which may be useful in certain environment (such as Tapestry applications).
	 * Defaults to <code>false</code>.
	 */
	private boolean continueChainBeforeSuccessfulAuthentication = false;
	
	/**
	 * If <code>true</code>, will always redirect to the value of {@code defaultTargetUrl}
	 * (defaults to <code>false</code>).
	 */
	private boolean alwaysUseDefaultTargetUrl = false;
	
	private String defaultTargetUrl = "/";
	
	/**
	 * If this property is set, the current request will be checked for this a parameter
	 * with this name and the value used as the target URL if present.
	 *
	 * @param targetUrlParameter the name of the parameter containing the encoded target
	 * URL. Defaults to null.
	 */
	private String targetUrlParameter = "target";
	
	/**
	 * Defines whether only HTTP POST requests will be allowed by this filter. If set to
	 * true, and an authentication request is received which is not a POST request, an
	 * exception will be raised immediately and authentication will not be attempted. The
	 * &lt;tt&gt;unsuccessfulAuthentication()&lt;/tt&gt; method will be called as if handling a failed
	 * authentication.
	 * <p>
	 * Defaults to &lt;tt&gt;true&lt;/tt&gt; but may be overridden by subclasses.
	 */
	private boolean postOnly = true;
	
	/**
	 * If set to &lt;tt&gt;true&lt;/tt&gt;, performs a forward to the failure destination URL instead
	 * of a redirect. Defaults to &lt;tt&gt;false&lt;/tt&gt;.
	 */
	private boolean useForward = false;
	
	/**
	 * If set to {@code true} the {@code Referer} header will be used (if available).
	 * Defaults to {@code false}.
	 */
	private boolean useReferer = false;

	@NestedConfigurationProperty
	private SecurityHeadersProperties headers = new SecurityHeadersProperties();

	@NestedConfigurationProperty
	private SecurityHeaderCorsProperties cors = new SecurityHeaderCorsProperties();
	
	@NestedConfigurationProperty
	private SecurityHeaderCsrfProperties csrf = new SecurityHeaderCsrfProperties();

	@NestedConfigurationProperty
	private SecurityFailureRetryProperties retry = new SecurityFailureRetryProperties();

	@NestedConfigurationProperty
	private SecurityEntryPointProperties entryPoint = new SecurityEntryPointProperties();
	
	@NestedConfigurationProperty
	private SecurityRedirectProperties redirect = new SecurityRedirectProperties();

	@NestedConfigurationProperty
	private SecuritySessionMgtProperties sessionMgt = new SecuritySessionMgtProperties();
	
	/**
	 * If this property is set, the current request will be checked for this a parameter
	 * with this name and the value used as the target URL if present.
	 *
	 * @param targetUrlParameter the name of the parameter containing the encoded target
	 * URL. Defaults to null.
	 */
	public void setTargetUrlParameter(String targetUrlParameter) {
		if (targetUrlParameter != null) {
			Assert.hasText(targetUrlParameter, "targetUrlParameter cannot be empty");
		}
		this.targetUrlParameter = targetUrlParameter;
	}

}
