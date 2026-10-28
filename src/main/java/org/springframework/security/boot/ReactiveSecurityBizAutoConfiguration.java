package org.springframework.security.boot;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.extension.web.server.ReactiveLocaleContextFilter;
import org.springframework.extension.web.server.ReactiveRequestContextFilter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.reactive.ReactiveSecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.boot.biz.authentication.server.*;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.NoOpAccessDeniedHandler;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.web.server.i18n.LocaleContextResolver;

import java.util.stream.Collectors;

/**
 * Reactive (WebFlux) counterpart of {@link SecurityBizAutoConfiguration}.
 * <p>
 * Registers the common reactive security infrastructure beans: locale/context
 * filters, matched authentication entry points, success/failure handlers,
 * access-denied handler and logout success handler. Runs before Spring Boot's
 * {@link ReactiveSecurityAutoConfiguration} and only takes effect in
 * reactive web applications.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@Configuration
@AutoConfigureBefore(ReactiveSecurityAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnClass(DefaultAuthenticationEventPublisher.class)
public class ReactiveSecurityBizAutoConfiguration {

	/**
	 * Creates the reactive locale-context filter; ordered with the highest precedence.
	 *
	 * @param localeContextResolver the locale context resolver to use
	 * @return a {@link ReactiveLocaleContextFilter}
	 */
	@Bean
	@ConditionalOnMissingBean
	@Order(value = Ordered.HIGHEST_PRECEDENCE)
	protected ReactiveLocaleContextFilter localeContextFilter(LocaleContextResolver localeContextResolver) {
		return new ReactiveLocaleContextFilter(localeContextResolver);
	}

	/**
	 * @return a {@link ReactiveRequestContextFilter} exposing request-scoped context.
	 */
	@Bean
	@Order(value = Ordered.HIGHEST_PRECEDENCE)
	@ConditionalOnMissingBean
	public ReactiveRequestContextFilter requestContextFilter() {
		return new ReactiveRequestContextFilter();
	}

	/**
	 * @return a {@link DefaultMatchedServerAuthenticationFailureHandler} that
	 *         delegates to a matching failure handler by exception type.
	 */
	@Bean
	@ConditionalOnMissingBean
	public DefaultMatchedServerAuthenticationFailureHandler defaultMatchedServerAuthenticationFailureHandler() {
		return new DefaultMatchedServerAuthenticationFailureHandler();
	}

	/**
	 * @return a {@link DefaultMatchedServerAuthenticationEntryPoint} that
	 *         delegates to a matching entry point by request matcher.
	 */
	@Bean
	@ConditionalOnMissingBean
	public DefaultMatchedServerAuthenticationEntryPoint defaultMatchedServerAuthenticationEntryPoint() {
		return new DefaultMatchedServerAuthenticationEntryPoint();
	}

	/**
	 * Aggregates all registered {@link MatchedServerAuthenticationEntryPoint}
	 * beans into a single reactive entry point.
	 *
	 * @param entryPointProvider object provider for the registered entry points
	 * @return a {@link ReactiveAuthenticationEntryPoint} composite
	 */
	@Bean
	@ConditionalOnMissingBean
	public ServerAuthenticationEntryPoint serverAuthenticationEntryPoint(
			ObjectProvider<MatchedServerAuthenticationEntryPoint> entryPointProvider) {
		return new ReactiveAuthenticationEntryPoint(entryPointProvider.stream().collect(Collectors.toList()));
	}

	/**
	 * Aggregates all registered {@link MatchedServerAuthenticationSuccessHandler}
	 * beans into a single reactive success handler.
	 *
	 * @param successHandlerProvider object provider for the registered success handlers
	 * @return a {@link ReactiveAuthenticationSuccessHandler} composite
	 */
	@Bean
	@ConditionalOnMissingBean
	public ServerAuthenticationSuccessHandler serverAuthenticationSuccessHandler(
			ObjectProvider<MatchedServerAuthenticationSuccessHandler> successHandlerProvider) {
		return new ReactiveAuthenticationSuccessHandler(successHandlerProvider.stream().collect(Collectors.toList()));
	}

	/**
	 * Aggregates all registered {@link MatchedServerAuthenticationFailureHandler}
	 * beans into a single reactive failure handler.
	 *
	 * @param failureHandlerProvider object provider for the registered failure handlers
	 * @return a {@link ReactiveAuthenticationFailureHandler} composite
	 */
	@Bean
	@ConditionalOnMissingBean
	public ServerAuthenticationFailureHandler serverAuthenticationFailureHandler(
			ObjectProvider<MatchedServerAuthenticationFailureHandler> failureHandlerProvider) {
		return new ReactiveAuthenticationFailureHandler(failureHandlerProvider.stream().collect(Collectors.toList()));
	}

	/**
	 * @return a {@link ReactiveServerAccessDeniedHandler} handling reactive 403 responses.
	 */
	@Bean
	@ConditionalOnMissingBean
	public ReactiveServerAccessDeniedHandler serverAccessDeniedHandler() {
		return new ReactiveServerAccessDeniedHandler();
	}

	/**
	 * @return a {@link ReactiveServerLogoutSuccessHandler} handling reactive logout completion.
	 */
	@Bean
	@ConditionalOnMissingBean
	public ServerLogoutSuccessHandler serverLogoutSuccessHandler() {
		return new ReactiveServerLogoutSuccessHandler();
	}

	/**
	 * @return a {@link NoOpAccessDeniedHandler} (no-op) used as a fallback.
	 */
	@Bean
	@ConditionalOnMissingBean
	public AccessDeniedHandler accessDeniedHandler(){
		return new NoOpAccessDeniedHandler();
	}

}
