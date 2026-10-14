package org.springframework.security.boot;

import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import hitool.core.lang3.time.DateFormats;
import javax.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.extension.web.servlet.i18n.LocaleContextFilter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.authentication.*;
import org.springframework.security.boot.biz.IgnoreLogoutHandler;
import org.springframework.security.boot.biz.authentication.AuthorizationPermissionEvaluator;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.authentication.captcha.NullCaptchaResolver;
import org.springframework.security.boot.biz.authentication.nested.DefaultMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.DefaultMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.property.SessionFixationPolicy;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.session.*;
import org.springframework.web.servlet.LocaleResolver;

import java.util.stream.Collectors;

/**
 * Spring Boot auto-configuration that wires the common infrastructure beans
 * shared by the security-biz starter: authentication details source, HTTP
 * firewall, password encoder, JSON mapper, authorities mapper, permission
 * evaluator, captcha resolver, authentication manager, session-management
 * helpers and the logout / access-denied handlers.
 * <p>
 * All beans are guarded by {@code @ConditionalOnMissingBean} so applications
 * can override any of them. The configuration runs before Spring Boot's
 * {@link SecurityAutoConfiguration} and only takes effect in servlet web
 * applications.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@Configuration
@AutoConfigureBefore(SecurityAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(DefaultAuthenticationEventPublisher.class)
@EnableConfigurationProperties({ SecurityBizProperties.class, SecuritySessionMgtProperties.class })
public class SecurityBizAutoConfiguration {

	/**
	 * @return the {@link org.springframework.security.web.authentication.WebAuthenticationDetailsSource}
	 *         used to populate authentication details from request instances.
	 */
	@Bean
	@ConditionalOnMissingBean
	public AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource() {
		return new WebAuthenticationDetailsSource();
	}

	/**
	 * Creates the locale-context filter that resolves the current locale for
	 * each request; ordered with the highest precedence.
	 *
	 * @param localeResolver the locale resolver to use
	 * @return a {@link LocaleContextFilter}
	 */
	@Bean
	@Order(value = Ordered.HIGHEST_PRECEDENCE)
	protected LocaleContextFilter localeContextFilter(LocaleResolver localeResolver) {
		return new LocaleContextFilter(localeResolver);
	}

	/**
	 * @return a {@link StrictHttpFirewall} used to validate and sanitise requests.
	 */
	@Bean
	@ConditionalOnMissingBean
	protected HttpFirewall httpFirewall() {
		return new StrictHttpFirewall();
	}

	/**
	 * @return a {@link BCryptPasswordEncoder} used to hash and verify passwords.
	 */
	@Bean
	@ConditionalOnMissingBean
	protected PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	/**
	 * @return a leniently-configured Jackson {@link ObjectMapper} for security
	 *         JSON serialisation (long date format, no fail-on-empty/unknown).
	 */
	@Bean
	@ConditionalOnMissingBean
	public ObjectMapper objectMapper() {
		return Jackson2ObjectMapperBuilder.json()
				.simpleDateFormat(DateFormats.DATE_LONGFORMAT)
				.failOnEmptyBeans(false)
				.failOnUnknownProperties(false)
				.featuresToEnable(MapperFeature.USE_GETTERS_AS_SETTERS, MapperFeature.ALLOW_FINAL_FIELDS_AS_MUTATORS).build();
	}

	/**
	 * @return a {@link NullAuthoritiesMapper} (passes authorities through unchanged).
	 */
	@Bean
	@ConditionalOnMissingBean
	public GrantedAuthoritiesMapper authoritiesMapper() {
		return new NullAuthoritiesMapper();
	}

	/**
	 * @return an {@link AuthorizationPermissionEvaluator} used in SpEL-based access rules.
	 */
	@Bean
	@ConditionalOnMissingBean
	public PermissionEvaluator permissionEvaluator() {
		return new AuthorizationPermissionEvaluator();
	}

	/**
	 * @return a {@link NullCaptchaResolver} (no captcha validation) used as a fallback.
	 */
    @Bean
	@ConditionalOnMissingBean
	public CaptchaResolver captchaResolver() {
		return new NullCaptchaResolver();
	}

	/**
	 * @return an {@link IgnoreLogoutHandler} that performs no-op logout processing.
	 */
    @Bean
   	@ConditionalOnMissingBean
   	public LogoutHandler ignoreLogoutHandler() {
   		return new IgnoreLogoutHandler();
   	}

	/**
	 * Creates the {@link AuthenticationManager} from all registered
	 * {@link AuthenticationProvider} beans. Credential erasure is disabled so
	 * downstream code can still access the credentials after authentication.
	 *
	 * @param authenticationProvider object provider for the registered authentication providers
	 * @return a {@link ProviderManager} aggregating the providers
	 */
    @Bean
	@ConditionalOnMissingBean
	protected AuthenticationManager authenticationManager(ObjectProvider<AuthenticationProvider> authenticationProvider) {
    	ProviderManager authenticationManager = new ProviderManager(authenticationProvider.stream().collect(Collectors.toList()));
		authenticationManager.setEraseCredentialsAfterAuthentication(false);
		return authenticationManager;
	}

	/**
	 * @return an {@link HttpSessionEventPublisher} so Spring Security receives
	 *         HTTP session lifecycle events.
	 */
	@Bean
	@ConditionalOnMissingBean
	protected HttpSessionEventPublisher httpSessionEventPublisher() {
		return new HttpSessionEventPublisher();
	}

	/**
	 * @return a {@link DefaultMatchedAuthenticationFailureHandler} that delegates
	 *         to a matching failure handler by exception type.
	 */
	@Bean
	@ConditionalOnMissingBean
	public DefaultMatchedAuthenticationFailureHandler defaultMatchedAuthenticationFailureHandler() {
		return new DefaultMatchedAuthenticationFailureHandler();
	}

	/**
	 * @return a {@link DefaultMatchedAuthenticationEntryPoint} that delegates to
	 *         a matching entry point by request matcher.
	 */
	@Bean
	@ConditionalOnMissingBean
	public DefaultMatchedAuthenticationEntryPoint defaultMatchedAuthenticationEntryPoint() {
		return new DefaultMatchedAuthenticationEntryPoint();
	}

	/**
	 * @return a {@link NullRememberMeServices} (remember-me disabled) used as a fallback.
	 */
	@Bean
	@ConditionalOnMissingBean
	public RememberMeServices rememberMeServices() {
 		return new NullRememberMeServices();
 	}

	/**
	 * @return a {@link SessionRegistryImpl} tracking active HTTP sessions.
	 */
	@Bean
	@ConditionalOnMissingBean
	public SessionRegistry sessionRegistry() {
 		return new SessionRegistryImpl();
 	}

	/**
	 * Creates the strategy used when a concurrent session has expired.
	 *
	 * @param sessionMgtProperties session-management configuration
	 * @return a {@link SimpleRedirectSessionInformationExpiredStrategy}
	 *         redirecting to the configured failure URL
	 */
	@Bean
	@ConditionalOnMissingBean
	public SessionInformationExpiredStrategy expiredSessionStrategy(SecuritySessionMgtProperties sessionMgtProperties) {
 		return new SimpleRedirectSessionInformationExpiredStrategy(sessionMgtProperties.getFailureUrl());
 	}

	/**
	 * Creates the strategy used when a session is invalid.
	 *
	 * @param sessionMgtProperties session-management configuration
	 * @return a {@link SimpleRedirectInvalidSessionStrategy} redirecting to the
	 *         configured failure URL, optionally creating a new session
	 */
	@Bean
	@ConditionalOnMissingBean
	public InvalidSessionStrategy invalidSessionStrategy(SecuritySessionMgtProperties sessionMgtProperties) {
		SimpleRedirectInvalidSessionStrategy invalidSessionStrategy = new SimpleRedirectInvalidSessionStrategy(
				sessionMgtProperties.getFailureUrl());
		invalidSessionStrategy.setCreateNewSession(sessionMgtProperties.isAllowSessionCreation());
		return invalidSessionStrategy;
	}

	/**
	 * @return an {@link AccessDeniedHandlerImpl} that surfaces 403 errors.
	 */
	@Bean
	@ConditionalOnMissingBean
	public AccessDeniedHandler accessDeniedHandler() {
		AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();
		return accessDeniedHandler;
	}

	/**
	 * @return an {@link HttpStatusReturningLogoutSuccessHandler} returning the
	 *         logout success status code.
	 */
	@Bean
	@ConditionalOnMissingBean
	public LogoutSuccessHandler logoutSuccessHandler() {
		return new HttpStatusReturningLogoutSuccessHandler();
	}

	/**
	 * Creates the session-authentication strategy based on the configured
	 * session-fixation policy.
	 *
	 * @param sessionMgtProperties session-management configuration
	 * @return the matching {@link SessionAuthenticationStrategy}
	 */
	@Bean
	@ConditionalOnMissingBean
	public SessionAuthenticationStrategy sessionAuthenticationStrategy(SecuritySessionMgtProperties sessionMgtProperties) {
 		// Session manager configuration parameters.
 		if (SessionFixationPolicy.CHANGE_SESSION_ID.equals(sessionMgtProperties.getFixationPolicy())) {
 			return new ChangeSessionIdAuthenticationStrategy();
 		} else if (SessionFixationPolicy.MIGRATE_SESSION.equals(sessionMgtProperties.getFixationPolicy())) {
 			return new SessionFixationProtectionStrategy();
 		} else if (SessionFixationPolicy.NEW_SESSION.equals(sessionMgtProperties.getFixationPolicy())) {
 			SessionFixationProtectionStrategy sessionFixationProtectionStrategy = new SessionFixationProtectionStrategy();
 			sessionFixationProtectionStrategy.setMigrateSessionAttributes(false);
 			return sessionFixationProtectionStrategy;
 		} else {
 			return new NullAuthenticatedSessionStrategy();
 		}
 	}

}
