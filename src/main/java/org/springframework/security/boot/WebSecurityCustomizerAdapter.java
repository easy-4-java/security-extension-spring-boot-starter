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
package org.springframework.security.boot;

import org.apache.commons.lang3.ArrayUtils;
import org.springframework.beans.BeansException;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.boot.biz.CustomWebSecurityExpressionHandler;
import org.springframework.security.boot.biz.property.SecurityHeaderCorsProperties;
import org.springframework.security.boot.biz.property.SecurityHeaderCsrfProperties;
import org.springframework.security.boot.biz.property.SecurityHeadersProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.property.header.*;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.boot.utils.WebSecurityUtils;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.util.CollectionUtils;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.*;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


/**
 * Base adapter for building Spring Security {@link WebSecurityCustomizer}
 * instances used by the security-biz starter. Provides reusable hooks for
 * configuring the authentication manager, security headers, CSRF, CORS and the
 * rule-based authorization derived from the Shiro-style filter-chain
 * definition map.
 * <p>
 * Subclasses extend this adapter (see
 * {@link WebSecurityBizConfigurerAdapter}) to plug in authentication-specific
 * wiring while inheriting the common configuration helpers.</p>
 *
 * @see WebSecurityCustomizer
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public abstract class WebSecurityCustomizerAdapter implements WebSecurityCustomizer, ApplicationContextAware {

	/** Pattern matching {@code roles[...]} chain names, e.g. {@code roles[admin,user]}. */
	protected Pattern rolesPattern = Pattern.compile("roles\\[(\\S+)\\]");
	/** Pattern matching {@code perms[...]} chain names, e.g. {@code perms[user:read]}. */
	protected Pattern permsPattern = Pattern.compile("perms\\[(\\S+)\\]");
	/** Pattern matching {@code ipaddr[...]} chain names, e.g. {@code ipaddr[192.168.1.0/24]}. */
	protected Pattern ipaddrPattern = Pattern.compile("ipaddr\\[(\\S+)\\]");
	/** Bound business-level security properties (filter-chain definition map). */
	protected final SecurityBizProperties bizProperties;
	/** Bound session-management properties. */
	protected final SecuritySessionMgtProperties sessionMgtProperties;
	/** Authentication providers registered with this adapter. */
	protected final List<AuthenticationProvider> authenticationProviders;
	/** The application context, injected via {@link ApplicationContextAware}. */
	protected ApplicationContext applicationContext;

	/**
	 * Binds the business properties, session-management properties and
	 * authentication providers used by this adapter.
	 *
	 * @param bizProperties          business-level security properties
	 * @param sessionMgtProperties   session-management properties
	 * @param authenticationProviders authentication providers to register
	 */
	public WebSecurityCustomizerAdapter(SecurityBizProperties bizProperties,
										SecuritySessionMgtProperties sessionMgtProperties,
										List<AuthenticationProvider> authenticationProviders) {
		this.bizProperties = bizProperties;
		this.sessionMgtProperties = sessionMgtProperties;
		this.authenticationProviders = authenticationProviders;
	}

	/**
	 * Builds the {@link AuthenticationManager} from the registered providers.
	 * <p>Credential erasure is disabled so remember-me services can still
	 * access the credentials after authentication.</p>
	 *
	 * @return a {@link ProviderManager} aggregating the authentication providers
	 * @throws Exception if the manager cannot be built
	 */
	public AuthenticationManager authenticationManagerBean() throws Exception {
		ProviderManager authenticationManager = new ProviderManager(authenticationProviders);
		// Do not erase credentials: erasing would force TokenBasedRememberMeServices to
		// re-invoke UserDetailsService and throw UsernameNotFoundException.
		authenticationManager.setEraseCredentialsAfterAuthentication(false);
		return authenticationManager;
	}

	/**
	 * Registers every authentication provider with the given builder.
	 *
	 * @param auth the {@link AuthenticationManagerBuilder} to configure
	 * @throws Exception if a provider cannot be registered
	 */
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		for (AuthenticationProvider authenticationProvider : authenticationProviders) {
			auth.authenticationProvider(authenticationProvider);
		}
	}

	/**
	 * Configures the security response headers (content-type options, XSS
	 * protection, cache control, HSTS, frame options, HPKP, CSP, referrer
	 * policy, feature/permissions policy) according to the bound properties.
	 *
	 * @param http        the HttpSecurity to configure
	 * @param properties  the security headers properties
	 * @throws Exception if configuration fails
	 */
	@SuppressWarnings("rawtypes")
	protected void configure(HttpSecurity http, SecurityHeadersProperties properties) throws Exception {
		if (properties.isEnabled()) {

			http.headers((headers) -> {

				HeaderContentTypeOptionsProperties contentTypeOptions = properties.getContentTypeOptions();
				if (Objects.nonNull(contentTypeOptions) && contentTypeOptions.isEnabled()) {
					headers.contentTypeOptions(Customizer.withDefaults());
				}

				HeaderXssProtectionProperties xssProtectionProperties = properties.getXssProtection();
				if (Objects.nonNull(xssProtectionProperties) && xssProtectionProperties.isEnabled()) {
					headers.xssProtection(xXssConfig -> {
						if (xssProtectionProperties.isBlock()) {
							xXssConfig.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK);
						} else {
							xXssConfig.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED);
						}
					});
				} else {
					headers.xssProtection((xXssConfig) -> xXssConfig.headerValue(XXssProtectionHeaderWriter.HeaderValue.DISABLED));
				}

				HeaderCacheControlProperties cacheControl = properties.getCacheControl();
				if (Objects.nonNull(cacheControl) && cacheControl.isEnabled()) {
					headers.cacheControl(cacheControlConfig -> {
					});
				}

				HeaderHstsProperties hsts = properties.getHsts();
				if (Objects.nonNull(hsts) && hsts.isEnabled()) {
					headers.httpStrictTransportSecurity(hstsConfig -> {
						hstsConfig.includeSubDomains(hsts.isIncludeSubDomains())
									.maxAgeInSeconds(hsts.getMaxAgeInSeconds());
					});
				}

				HeaderFrameOptionsProperties frameOptions = properties.getFrameOptions();
				if (Objects.nonNull(frameOptions) && frameOptions.isEnabled()) {
					headers.frameOptions( config -> {
						if (frameOptions.isDeny()) {
							config.deny();
						} else if (frameOptions.isSameOrigin()) {
							config.sameOrigin();
						}
					});
				}

				HeaderHpkpProperties hpkp = properties.getHpkp();
				if (Objects.nonNull(hpkp) && hpkp.isEnabled()) {
					headers.httpPublicKeyPinning(config -> config
							.includeSubDomains(hpkp.isIncludeSubDomains())
							.maxAgeInSeconds(hpkp.getMaxAgeInSeconds())
							.reportOnly(hpkp.isReportOnly())
							.reportUri(hpkp.getReportUri())
							.withPins(hpkp.getPins())
							.addSha256Pins(hpkp.getSha256Pins()));
				} else {
					headers.httpPublicKeyPinning(config -> config.disable());
				}

				HeaderContentSecurityPolicyProperties contentSecurityPolicy = properties.getContentSecurityPolicy();
				if (Objects.nonNull(contentSecurityPolicy) && contentSecurityPolicy.isEnabled()) {
					headers.contentSecurityPolicy(config -> {
						config.policyDirectives(contentSecurityPolicy.getPolicyDirectives());
						if (contentSecurityPolicy.isReportOnly()) {
							config.reportOnly();
						}
					});
				}

				HeaderReferrerPolicyProperties referrerPolicy = properties.getReferrerPolicy();
				if (Objects.nonNull(referrerPolicy) && referrerPolicy.isEnabled()) {
					headers.referrerPolicy(config -> {
						config.policy(referrerPolicy.getPolicy());
					});
				}

				HeaderFeaturePolicyProperties featurePolicy = properties.getFeaturePolicy();
				if (Objects.nonNull(featurePolicy) && featurePolicy.isEnabled()) {
					headers.permissionsPolicy(config -> {
						config.policy(featurePolicy.getPolicyDirectives());
					});
				}

			});

		} else {
			http.headers((headers) -> {
				headers.cacheControl(cacheControl -> cacheControl.disable());
			});
		}
	}

	/**
	 * Configures CSRF protection. When enabled, a token repository is wired and
	 * the configured request matchers are ignored; when disabled CSRF is
	 * turned off entirely.
	 *
	 * @param http  the HttpSecurity to configure
	 * @param csrf  the CSRF properties
	 * @throws Exception if configuration fails
	 */
	protected void configure(HttpSecurity http, SecurityHeaderCsrfProperties csrf) throws Exception {
		// CSRF configuration.
		if (csrf.isEnabled()) {
			http.csrf(csrfConfigurer -> {
				csrfConfigurer.csrfTokenRepository(WebSecurityUtils.csrfTokenRepository(sessionMgtProperties))
						.ignoringRequestMatchers(StringUtils.tokenizeToStringArray(csrf.getIgnoringAntMatchers()));
			});
		} else {
			http.csrf((csrfConfigurer) -> csrfConfigurer.disable());
		}
	}

	/**
	 * Customises the {@link WebSecurity} by ignoring the {@code anon} patterns
	 * declared in the filter-chain definition map (and all {@code OPTIONS}
	 * requests), so those requests bypass the security filter chain entirely.
	 *
	 * @param web the {@link WebSecurity} to customise
	 */
	@Override
	public void customize(WebSecurity web) {

		// Group the filter chain entries by filter (chain) name.
		Map<Object, List<Entry<String, String>>> groupingMap = bizProperties.getFilterChainDefinitionMap().entrySet()
				.stream().collect(Collectors.groupingBy(Entry::getValue, TreeMap::new, Collectors.toList()));

		List<Entry<String, String>> noneEntries = groupingMap.get("anon");
		List<String> permitMatchers = new ArrayList<String>();
		if (!CollectionUtils.isEmpty(noneEntries)) {
			permitMatchers = noneEntries.stream().map(mapper -> mapper.getKey()).collect(Collectors.toList());
		}
		web.ignoring()
				.requestMatchers(permitMatchers.toArray(new String[permitMatchers.size()]))
				.requestMatchers(HttpMethod.OPTIONS, "/**");

	}

	/**
	 * Builds a {@link UrlBasedCorsConfigurationSource} from the bound CORS
	 * properties.
	 *
	 * @param cors the CORS properties
	 * @return the configured CORS configuration source
	 */
	protected CorsConfigurationSource configurationSource(SecurityHeaderCorsProperties cors) {

		UrlBasedCorsConfigurationSource configurationSource = new UrlBasedCorsConfigurationSource();

		// Apply all non-null bound properties onto the source.
		PropertyMapper map = PropertyMapper.get();

		map.from(cors.isAlwaysUseFullPath()).to(configurationSource::setAlwaysUseFullPath);
		map.from(cors.getCorsConfigurations()).to(configurationSource::setCorsConfigurations);
		map.from(cors.isRemoveSemicolonContent()).to(configurationSource::setRemoveSemicolonContent);
		map.from(cors.isUrlDecode()).to(configurationSource::setUrlDecode);

		return configurationSource;
	}

	/**
	 * Configures the rule-based authorization for the given {@link HttpSecurity}
	 * by parsing the Shiro-style chain names from the filter-chain definition
	 * map: {@code roles[...]}, {@code perms[...]} and {@code ipaddr[...]}.
	 *
	 * @param http the HttpSecurity to configure
	 * @throws Exception if configuration fails
	 */
	protected void configure(HttpSecurity http) throws Exception {

		// Group the filter chain entries by filter (chain) name.
		Map<Object, List<Entry<String, String>>> groupingMap = bizProperties.getFilterChainDefinitionMap().entrySet()
				.stream().collect(Collectors.groupingBy(Entry::getValue, TreeMap::new, Collectors.toList()));

		// https://www.jianshu.com/p/01498e0e0c83
		Set<Object> keySet = groupingMap.keySet();
		for (Object key : keySet) {
			// Ant表达式 = roles[xxx]
			Matcher rolesMatcher = rolesPattern.matcher(key.toString());
			if (rolesMatcher.find()) {

				List<String> antPatterns = groupingMap.get(key.toString()).stream().map(Entry::getKey).collect(Collectors.toList());
				// 角色
				String[] roles = StringUtils.split(rolesMatcher.group(1), ",");
				if (ArrayUtils.isNotEmpty(roles)) {
					if (roles.length > 1) {
						// 如果用户具备给定角色中的某一个的话，就允许访问
						http.authorizeHttpRequests(authorize -> authorize
								.requestMatchers(antPatterns.toArray(new String[antPatterns.size()]))
								.hasAnyRole(roles));
					} else {
						// 如果用户具备给定角色的话，就允许访问
						http.authorizeHttpRequests(authorize -> authorize
								.requestMatchers(antPatterns.toArray(new String[antPatterns.size()]))
								.hasRole(roles[0]));
					}
				}
			}
			// Ant表达式 = perms[xxx]
			Matcher permsMatcher = permsPattern.matcher(key.toString());
			if (permsMatcher.find()) {

				List<String> antPatterns = groupingMap.get(key.toString()).stream().map(Entry::getKey).collect(Collectors.toList());
				// 权限标记
				String[] perms = StringUtils.split(permsMatcher.group(1), ",");
				if (ArrayUtils.isNotEmpty(perms)) {
					if (perms.length > 1) {
						// 如果用户具备给定全权限的某一个的话，就允许访问
						http.authorizeHttpRequests(authorize -> authorize
								.requestMatchers(antPatterns.toArray(new String[antPatterns.size()]))
								.hasAnyAuthority(perms));
					} else {
						// 如果用户具备给定权限的话，就允许访问
						http.authorizeHttpRequests(authorize -> authorize
								.requestMatchers(antPatterns.toArray(new String[antPatterns.size()]))
								.hasAuthority(perms[0]));
					}
				}
			}
			// Ant表达式 = ipaddr[192.168.1.0/24]
			Matcher ipMatcher = ipaddrPattern.matcher(key.toString());
			if (ipMatcher.find()) {

				List<String> antPatterns = groupingMap.get(key.toString()).stream().map(Entry::getKey).collect(Collectors.toList());
				// ipaddress
				String ipaddr = ipMatcher.group(1);
				if (StringUtils.hasText(ipaddr)) {
					// 如果请求来自给定IP地址的话，就允许访问
					WebExpressionAuthorizationManager authorizationManager =
							new WebExpressionAuthorizationManager("hasIpAddress('" + ipaddr + "')");
					authorizationManager.setExpressionHandler(customWebSecurityExpressionHandler());
					http.authorizeHttpRequests(authorize -> authorize
							.requestMatchers(antPatterns.toArray(new String[antPatterns.size()]))
							.access(authorizationManager));
				}
			}
		}
	}

	/**
	 * @return a {@link CustomWebSecurityExpressionHandler} for SpEL-based access rules.
	 */
	public SecurityExpressionHandler<RequestAuthorizationContext> customWebSecurityExpressionHandler() {
		return new CustomWebSecurityExpressionHandler();
	}

	/**
	 * Configures CORS for the given {@link HttpSecurity} using the bound CORS
	 * properties; disables CORS entirely when the properties are absent or disabled.
	 *
	 * @param http           the HttpSecurity to configure
	 * @param corsProperties the CORS properties
	 * @throws Exception if configuration fails
	 */
	protected void configure(HttpSecurity http, SecurityHeaderCorsProperties corsProperties) throws Exception {
		if (Objects.nonNull(corsProperties) && corsProperties.isEnabled()) {
			http.cors(config -> config.configurationSource(this.configurationSource(corsProperties)));
		} else {
			http.cors(config -> config.disable());
		}
	}

	/** @return the bound session-management properties. */
	public SecuritySessionMgtProperties getSessionMgtProperties() {
		return sessionMgtProperties;
	}

	/**
	 * Stores the {@link ApplicationContext} injected by Spring.
	 *
	 * @param applicationContext the running application context
	 * @throws BeansException never thrown by the current implementation
	 */
	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	/** @return the application context. */
	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}

}
