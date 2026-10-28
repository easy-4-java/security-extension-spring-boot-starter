package org.springframework.security.boot.biz.authentication;

import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Tests for PostRequestAuthenticationProcessingFilter, PostOnlyAuthenticationProcessingFilter,
 * AuthenticationProcessingFilter, and PostRequestAuthenticationProvider.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class FiltersAndProviderTest {

    // --- PostRequestAuthenticationProcessingFilter ---

    @Test
    void postRequestFilterConstructorWithObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        PostRequestAuthenticationProcessingFilter filter = new PostRequestAuthenticationProcessingFilter(mapper);
        assertThat(filter).isNotNull();
        assertThat(filter.getObjectMapper()).isEqualTo(mapper);
    }

    @Test
    void postRequestFilterConstructorWithObjectMapperAndMatcher() {
        ObjectMapper mapper = new ObjectMapper();
        PathPatternRequestMatcher matcher = PathPatternRequestMatcher.pathPattern("/auth");
        PostRequestAuthenticationProcessingFilter filter = new PostRequestAuthenticationProcessingFilter(mapper, matcher);
        assertThat(filter).isNotNull();
    }

    @Test
    void postRequestFilterGettersAndSetters() {
        ObjectMapper mapper = new ObjectMapper();
        PostRequestAuthenticationProcessingFilter filter = new PostRequestAuthenticationProcessingFilter(mapper);

        filter.setUsernameParameter("user");
        assertThat(filter.getUsernameParameter()).isEqualTo("user");

        filter.setPasswordParameter("pwd");
        assertThat(filter.getPasswordParameter()).isEqualTo("pwd");

        filter.setCaptchaRequired(true);
        assertThat(filter.isCaptchaRequired()).isTrue();

        filter.setCaptchaParameter("cap");
        assertThat(filter.getCaptchaParameter()).isEqualTo("cap");

        filter.setPostOnly(false);
        assertThat(filter.isPostOnly()).isFalse();

        filter.setRetryTimesKeyAttribute("retryKey");
        assertThat(filter.getRetryTimesKeyAttribute()).isEqualTo("retryKey");

        filter.setRetryTimesWhenAccessDenied(5);
        assertThat(filter.getRetryTimesWhenAccessDenied()).isEqualTo(5);
    }

    @Test
    void postRequestFilterFailureCounter() {
        ObjectMapper mapper = new ObjectMapper();
        PostRequestAuthenticationProcessingFilter filter = new PostRequestAuthenticationProcessingFilter(mapper);
        assertThat(filter.getFailureCounter()).isNull();
        AuthenticatingFailureCounter counter = mock(AuthenticatingFailureCounter.class);
        filter.setFailureCounter(counter);
        assertThat(filter.getFailureCounter()).isEqualTo(counter);
    }

    @Test
    void postRequestFilterCaptchaResolver() {
        ObjectMapper mapper = new ObjectMapper();
        PostRequestAuthenticationProcessingFilter filter = new PostRequestAuthenticationProcessingFilter(mapper);
        assertThat(filter.getCaptchaResolver()).isNull();
        CaptchaResolver resolver = mock(CaptchaResolver.class);
        filter.setCaptchaResolver(resolver);
        assertThat(filter.getCaptchaResolver()).isEqualTo(resolver);
    }

    @Test
    void postRequestFilterConstants() {
        assertThat(PostRequestAuthenticationProcessingFilter.SPRING_SECURITY_FORM_USERNAME_KEY).isEqualTo("username");
        assertThat(PostRequestAuthenticationProcessingFilter.SPRING_SECURITY_FORM_PASSWORD_KEY).isEqualTo("password");
        assertThat(PostRequestAuthenticationProcessingFilter.SPRING_SECURITY_FORM_CAPTCHA_KEY).isEqualTo("captcha");
        assertThat(PostRequestAuthenticationProcessingFilter.DEFAULT_RETRY_TIMES_KEY_ATTRIBUTE_NAME).isEqualTo("securityLoginFailureRetries");
    }

    @Test
    void postRequestFilterDefaultValues() {
        ObjectMapper mapper = new ObjectMapper();
        PostRequestAuthenticationProcessingFilter filter = new PostRequestAuthenticationProcessingFilter(mapper);
        assertThat(filter.getUsernameParameter()).isEqualTo("username");
        assertThat(filter.getPasswordParameter()).isEqualTo("password");
        assertThat(filter.isCaptchaRequired()).isFalse();
        assertThat(filter.getCaptchaParameter()).isEqualTo("captcha");
        assertThat(filter.isPostOnly()).isTrue();
        assertThat(filter.getRetryTimesKeyAttribute()).isEqualTo("securityLoginFailureRetries");
        assertThat(filter.getRetryTimesWhenAccessDenied()).isEqualTo(3);
    }

    // --- PostOnlyAuthenticationProcessingFilter ---

    @Test
    void postOnlyFilterDefaultPostOnly() {
        ObjectMapper mapper = new ObjectMapper();
        PostRequestAuthenticationProcessingFilter filter = new PostRequestAuthenticationProcessingFilter(mapper);
        assertThat(filter.isPostOnly()).isTrue();
        filter.setPostOnly(false);
        assertThat(filter.isPostOnly()).isFalse();
    }

    // --- AuthenticationProcessingFilter constants ---

    @Test
    void authenticationProcessingFilterConstants() {
        assertThat(AuthenticationProcessingFilter.DEFAULT_LONGITUDE_LATITUDE).isEqualTo("0.000000");
        assertThat(AuthenticationProcessingFilter.UID_HEADER).isEqualTo("X-Uid");
        assertThat(AuthenticationProcessingFilter.SIGN_HEADER).isEqualTo("X-Sign");
        assertThat(AuthenticationProcessingFilter.LONGITUDE_HEADER).isEqualTo("X-Longitude");
        assertThat(AuthenticationProcessingFilter.LATITUDE_HEADER).isEqualTo("X-Latitude");
        assertThat(AuthenticationProcessingFilter.APP_ID_HEADER).isEqualTo("X-APP-ID");
        assertThat(AuthenticationProcessingFilter.APP_CHANNEL_HEADER).isEqualTo("X-APP-CHANNEL");
        assertThat(AuthenticationProcessingFilter.APP_VERSION_HEADER).isEqualTo("X-APP-VERSION");
    }

    // --- PostRequestAuthenticationProvider ---

    @Test
    void providerAuthenticateWithEmptyUsername() {
        UserDetailsServiceAdapter userDetailsService = mock(UserDetailsServiceAdapter.class);
        org.springframework.security.crypto.password.PasswordEncoder passwordEncoder = mock(org.springframework.security.crypto.password.PasswordEncoder.class);
        PostRequestAuthenticationProvider provider = new PostRequestAuthenticationProvider(userDetailsService, passwordEncoder);

        org.springframework.security.authentication.UsernamePasswordAuthenticationToken auth =
                new org.springframework.security.authentication.UsernamePasswordAuthenticationToken("", "password");

        try {
            provider.authenticate(auth);
        } catch (Exception e) {
            assertThat(e).isInstanceOf(org.springframework.security.authentication.BadCredentialsException.class);
        }
    }

    @Test
    void providerAuthenticateWithEmptyPassword() {
        UserDetailsServiceAdapter userDetailsService = mock(UserDetailsServiceAdapter.class);
        org.springframework.security.crypto.password.PasswordEncoder passwordEncoder = mock(org.springframework.security.crypto.password.PasswordEncoder.class);
        PostRequestAuthenticationProvider provider = new PostRequestAuthenticationProvider(userDetailsService, passwordEncoder);

        org.springframework.security.authentication.UsernamePasswordAuthenticationToken auth =
                new org.springframework.security.authentication.UsernamePasswordAuthenticationToken("user", "");

        try {
            provider.authenticate(auth);
        } catch (Exception e) {
            assertThat(e).isInstanceOf(org.springframework.security.authentication.BadCredentialsException.class);
        }
    }

    @Test
    void providerAuthenticateWithNullAuth() {
        UserDetailsServiceAdapter userDetailsService = mock(UserDetailsServiceAdapter.class);
        org.springframework.security.crypto.password.PasswordEncoder passwordEncoder = mock(org.springframework.security.crypto.password.PasswordEncoder.class);
        PostRequestAuthenticationProvider provider = new PostRequestAuthenticationProvider(userDetailsService, passwordEncoder);

        try {
            provider.authenticate(null);
        } catch (Exception e) {
            assertThat(e).isInstanceOf(IllegalArgumentException.class);
        }
    }

    // --- PostLoginRequest ---

    @Test
    void postLoginRequestAllGetters() {
        PostLoginRequest req = new PostLoginRequest("user", "pass", "cap");
        assertThat(req.getUsername()).isEqualTo("user");
        assertThat(req.getPassword()).isEqualTo("pass");
        assertThat(req.getCaptcha()).isEqualTo("cap");
    }

    @Test
    void postLoginRequestAllSetters() {
        PostLoginRequest req = new PostLoginRequest(null, null, null);
        req.setUsername("u");
        req.setPassword("p");
        req.setCaptcha("c");
        assertThat(req.getUsername()).isEqualTo("u");
        assertThat(req.getPassword()).isEqualTo("p");
        assertThat(req.getCaptcha()).isEqualTo("c");
    }
}
