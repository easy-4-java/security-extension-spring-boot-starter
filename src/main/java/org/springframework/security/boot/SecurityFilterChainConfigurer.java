/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.springframework.security.boot;

import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecurityAuthcProperties;
import org.springframework.security.boot.biz.property.SecurityHeadersProperties;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.utils.WebSecurityUtils;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;
import java.util.Objects;

/**
 * Common servlet security-chain helper for feature starters.
 */
public abstract class SecurityFilterChainConfigurer {

	protected final SecurityBizProperties bizProperties;
	protected final RedirectStrategy redirectStrategy;
	protected final RequestCache requestCache;

	protected SecurityFilterChainConfigurer(SecurityBizProperties bizProperties,
			RedirectStrategy redirectStrategy,
			RequestCache requestCache) {
		this.bizProperties = bizProperties;
		this.redirectStrategy = redirectStrategy;
		this.requestCache = requestCache;
	}

	protected AuthenticationEntryPoint authenticationEntryPoint(String pathPattern,
			List<MatchedAuthenticationEntryPoint> entryPoints) {
		return new PostRequestAuthenticationEntryPoint(pathPattern, entryPoints);
	}

	protected AuthenticationSuccessHandler authenticationSuccessHandler(SecurityAuthcProperties authcProperties,
			List<AuthenticationListener> authenticationListeners,
			List<MatchedAuthenticationSuccessHandler> successHandlers) {
		PostRequestAuthenticationSuccessHandler successHandler =
				new PostRequestAuthenticationSuccessHandler(authenticationListeners, successHandlers);
		successHandler.setAlwaysUseDefaultTargetUrl(authcProperties.isAlwaysUseDefaultTargetUrl());
		successHandler.setDefaultTargetUrl(authcProperties.getSuccessUrl());
		successHandler.setRedirectStrategy(Objects.nonNull(redirectStrategy)
				? redirectStrategy : WebSecurityUtils.redirectStrategy(authcProperties));
		if (Objects.nonNull(requestCache)) {
			successHandler.setRequestCache(requestCache);
		}
		successHandler.setTargetUrlParameter(authcProperties.getTargetUrlParameter());
		successHandler.setUseReferer(authcProperties.isUseReferer());
		return successHandler;
	}

	protected AuthenticationFailureHandler authenticationFailureHandler(
			List<AuthenticationListener> authenticationListeners,
			List<MatchedAuthenticationFailureHandler> failureHandlers) {
		return new PostRequestAuthenticationFailureHandler(authenticationListeners, failureHandlers);
	}

	protected LogoutHandler logoutHandler(List<LogoutHandler> logoutHandlers) {
		return WebSecurityUtils.logoutHandler(logoutHandlers);
	}

	protected Customizer<ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry>
			authorizeRequestsCustomizer() {
		return registry -> registry.anyRequest().authenticated();
	}

	protected Customizer<HeadersConfigurer<HttpSecurity>> headersCustomizer(SecurityHeadersProperties headers) {
		return configurer -> {
			if (Objects.isNull(headers) || headers.isEnabled()) {
				return;
			}
			configurer.disable();
		};
	}

	protected Customizer<RequestCacheConfigurer<HttpSecurity>> requestCacheCustomizer() {
		return configurer -> {
			if (Objects.nonNull(requestCache)) {
				configurer.requestCache(requestCache);
			}
		};
	}

	protected Customizer<LogoutConfigurer<HttpSecurity>> logoutCustomizer(SecurityLogoutProperties logout,
			LogoutHandler logoutHandler,
			LogoutSuccessHandler logoutSuccessHandler) {
		return configurer -> {
			if (Objects.nonNull(logoutHandler)) {
				configurer.addLogoutHandler(logoutHandler);
			}
			if (Objects.nonNull(logoutSuccessHandler)) {
				configurer.logoutSuccessHandler(logoutSuccessHandler);
			}
			if (Objects.nonNull(logout) && Objects.nonNull(logout.getLogoutUrl())) {
				configurer.logoutUrl(logout.getLogoutUrl());
			}
		};
	}

	protected Customizer<SessionManagementConfigurer<HttpSecurity>> sessionManagementCustomizer(
			InvalidSessionStrategy invalidSessionStrategy,
			SessionRegistry sessionRegistry,
			SessionInformationExpiredStrategy sessionInformationExpiredStrategy,
			AuthenticationFailureHandler authenticationFailureHandler,
			SessionAuthenticationStrategy sessionAuthenticationStrategy) {
		return configurer -> {
			if (Objects.nonNull(invalidSessionStrategy)) {
				configurer.invalidSessionStrategy(invalidSessionStrategy);
			}
			if (Objects.nonNull(authenticationFailureHandler)) {
				configurer.sessionAuthenticationFailureHandler(authenticationFailureHandler);
			}
			if (Objects.nonNull(sessionAuthenticationStrategy)) {
				configurer.sessionAuthenticationStrategy(sessionAuthenticationStrategy);
			}
			if (Objects.nonNull(sessionRegistry) || Objects.nonNull(sessionInformationExpiredStrategy)) {
				SessionManagementConfigurer<HttpSecurity>.ConcurrencyControlConfigurer concurrency =
						configurer.maximumSessions(1);
				if (Objects.nonNull(sessionRegistry)) {
					concurrency.sessionRegistry(sessionRegistry);
				}
				if (Objects.nonNull(sessionInformationExpiredStrategy)) {
					concurrency.expiredSessionStrategy(sessionInformationExpiredStrategy);
				}
			}
		};
	}

	protected boolean isStateless(SessionCreationPolicy creationPolicy) {
		return SessionCreationPolicy.STATELESS.equals(creationPolicy);
	}

}
