package org.springframework.security.boot.utils;

import org.junit.jupiter.api.Test;
import org.springframework.security.boot.biz.utils.WebSecurityUtils;
import org.springframework.security.boot.biz.authentication.*;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.*;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.ForwardAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.ForwardLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.savedrequest.RequestCache;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Tests for WebSecurityUtils.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class WebSecurityUtilsTest {

    @Test
    void csrfTokenRepositoryWithChangeSessionId() {
        SecuritySessionMgtProperties props = new SecuritySessionMgtProperties();
        props.setFixationPolicy(SessionFixationPolicy.CHANGE_SESSION_ID);
        CsrfTokenRepository repo = WebSecurityUtils.csrfTokenRepository(props);
        assertThat(repo).isInstanceOf(CookieCsrfTokenRepository.class);
    }

    @Test
    void csrfTokenRepositoryWithOtherPolicy() {
        SecuritySessionMgtProperties props = new SecuritySessionMgtProperties();
        props.setFixationPolicy(SessionFixationPolicy.NONE);
        CsrfTokenRepository repo = WebSecurityUtils.csrfTokenRepository(props);
        assertThat(repo).isInstanceOf(HttpSessionCsrfTokenRepository.class);
    }

    @Test
    void authenticationEntryPoint() {
        SecurityAuthcProperties authcProps = new SecurityAuthcProperties();
        SecuritySessionMgtProperties sessionProps = new SecuritySessionMgtProperties();
        List<MatchedAuthenticationEntryPoint> entryPoints = Collections.emptyList();
        PostRequestAuthenticationEntryPoint ep = WebSecurityUtils.authenticationEntryPoint(authcProps, sessionProps, entryPoints);
        assertThat(ep).isNotNull();
    }

    @Test
    void authenticationFailureHandler() {
        SecurityAuthcProperties authcProps = new SecurityAuthcProperties();
        SecuritySessionMgtProperties sessionProps = new SecuritySessionMgtProperties();
        List<AuthenticationListener> listeners = Collections.emptyList();
        List<MatchedAuthenticationFailureHandler> handlers = Collections.emptyList();
        PostRequestAuthenticationFailureHandler handler = WebSecurityUtils.authenticationFailureHandler(authcProps, sessionProps, listeners, handlers);
        assertThat(handler).isNotNull();
    }

    @Test
    void authenticationSuccessHandler() {
        SecurityAuthcProperties authcProps = new SecurityAuthcProperties();
        SecuritySessionMgtProperties sessionProps = new SecuritySessionMgtProperties();
        List<AuthenticationListener> listeners = Collections.emptyList();
        List<MatchedAuthenticationSuccessHandler> handlers = Collections.emptyList();
        PostRequestAuthenticationSuccessHandler handler = WebSecurityUtils.authenticationSuccessHandler(authcProps, sessionProps, listeners, handlers);
        assertThat(handler).isNotNull();
    }

    @Test
    void requestCache() {
        SecurityAuthcProperties authcProps = new SecurityAuthcProperties();
        SecuritySessionMgtProperties sessionProps = new SecuritySessionMgtProperties();
        RequestCache cache = WebSecurityUtils.requestCache(authcProps, sessionProps);
        assertThat(cache).isNotNull();
    }

    @Test
    void redirectStrategy() {
        SecurityAuthcProperties authcProps = new SecurityAuthcProperties();
        RedirectStrategy strategy = WebSecurityUtils.redirectStrategy(authcProps);
        assertThat(strategy).isNotNull();
    }

    @Test
    void authenticatingFailureCounter() {
        SecurityAuthcProperties authcProps = new SecurityAuthcProperties();
        AuthenticatingFailureCounter counter = WebSecurityUtils.authenticatingFailureCounter(authcProps);
        assertThat(counter).isNotNull();
        assertThat(counter).isInstanceOf(AuthenticatingFailureRequestCounter.class);
    }

    @Test
    void authenticationFailureForwardHandler() {
        ForwardAuthenticationFailureHandler handler = WebSecurityUtils.authenticationFailureForwardHandler("/forward");
        assertThat(handler).isNotNull();
    }

    @Test
    void authenticationFailureSimpleUrlHandler() {
        SecurityAuthcProperties authcProps = new SecurityAuthcProperties();
        SecuritySessionMgtProperties sessionProps = new SecuritySessionMgtProperties();
        SimpleUrlAuthenticationFailureHandler handler = WebSecurityUtils.authenticationFailureSimpleUrlHandler(authcProps, sessionProps);
        assertThat(handler).isNotNull();
    }

    @Test
    void authenticationProvider() {
        UserDetailsServiceAdapter userDetailsService = mock(UserDetailsServiceAdapter.class);
        org.springframework.security.crypto.password.PasswordEncoder passwordEncoder = mock(org.springframework.security.crypto.password.PasswordEncoder.class);
        PostRequestAuthenticationProvider provider = WebSecurityUtils.authenticationProvider(userDetailsService, passwordEncoder);
        assertThat(provider).isNotNull();
    }

    @Test
    void logoutHandler() {
        LogoutHandler mockHandler = mock(LogoutHandler.class);
        List<LogoutHandler> handlers = List.of(mockHandler);
        LogoutHandler handler = WebSecurityUtils.logoutHandler(handlers);
        assertThat(handler).isInstanceOf(CompositeLogoutHandler.class);
    }

    @Test
    void logoutSuccessForwardHandler() {
        LogoutSuccessHandler handler = WebSecurityUtils.logoutSuccessForwardHandler("/logout-success");
        assertThat(handler).isInstanceOf(ForwardLogoutSuccessHandler.class);
    }
}
