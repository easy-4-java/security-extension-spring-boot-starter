package org.springframework.security.boot.biz.property;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link SecurityAuthcProperties}.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class SecurityAuthcPropertiesTest {

    @Test
    void defaultValues() {
        SecurityAuthcProperties props = new SecurityAuthcProperties();
        assertThat(props.getPathPattern()).isEqualTo("/login");
        assertThat(props.getRedirectUrl()).isEqualTo("/");
        assertThat(props.getSuccessUrl()).isEqualTo("/index");
        assertThat(props.getFailureUrl()).isEqualTo("/error");
        assertThat(props.isContinueChainBeforeSuccessfulAuthentication()).isFalse();
        assertThat(props.isAlwaysUseDefaultTargetUrl()).isFalse();
        assertThat(props.getDefaultTargetUrl()).isEqualTo("/");
        assertThat(props.getTargetUrlParameter()).isEqualTo("target");
        assertThat(props.isPostOnly()).isTrue();
        assertThat(props.isUseForward()).isFalse();
        assertThat(props.isUseReferer()).isFalse();
        assertThat(props.getHeaders()).isNotNull();
        assertThat(props.getCors()).isNotNull();
        assertThat(props.getCsrf()).isNotNull();
        assertThat(props.getRetry()).isNotNull();
        assertThat(props.getEntryPoint()).isNotNull();
        assertThat(props.getRedirect()).isNotNull();
        assertThat(props.getSessionMgt()).isNotNull();
    }

    @Test
    void setAndGetPathPattern() {
        SecurityAuthcProperties props = new SecurityAuthcProperties();
        props.setPathPattern("/custom-login");
        assertThat(props.getPathPattern()).isEqualTo("/custom-login");
    }

    @Test
    void setAndGetRedirectUrl() {
        SecurityAuthcProperties props = new SecurityAuthcProperties();
        props.setRedirectUrl("/home");
        assertThat(props.getRedirectUrl()).isEqualTo("/home");
    }

    @Test
    void setAndGetSuccessUrl() {
        SecurityAuthcProperties props = new SecurityAuthcProperties();
        props.setSuccessUrl("/dashboard");
        assertThat(props.getSuccessUrl()).isEqualTo("/dashboard");
    }

    @Test
    void setAndGetFailureUrl() {
        SecurityAuthcProperties props = new SecurityAuthcProperties();
        props.setFailureUrl("/login-error");
        assertThat(props.getFailureUrl()).isEqualTo("/login-error");
    }

    @Test
    void setContinueChainBeforeSuccessfulAuthentication() {
        SecurityAuthcProperties props = new SecurityAuthcProperties();
        props.setContinueChainBeforeSuccessfulAuthentication(true);
        assertThat(props.isContinueChainBeforeSuccessfulAuthentication()).isTrue();
    }

    @Test
    void setAlwaysUseDefaultTargetUrl() {
        SecurityAuthcProperties props = new SecurityAuthcProperties();
        props.setAlwaysUseDefaultTargetUrl(true);
        assertThat(props.isAlwaysUseDefaultTargetUrl()).isTrue();
    }

    @Test
    void setAndGetDefaultTargetUrl() {
        SecurityAuthcProperties props = new SecurityAuthcProperties();
        props.setDefaultTargetUrl("/welcome");
        assertThat(props.getDefaultTargetUrl()).isEqualTo("/welcome");
    }

    @Test
    void setAndGetTargetUrlParameter() {
        SecurityAuthcProperties props = new SecurityAuthcProperties();
        props.setTargetUrlParameter("redirect");
        assertThat(props.getTargetUrlParameter()).isEqualTo("redirect");
    }

    @Test
    void setTargetUrlParameterToNull() {
        SecurityAuthcProperties props = new SecurityAuthcProperties();
        props.setTargetUrlParameter(null);
        assertThat(props.getTargetUrlParameter()).isNull();
    }

    @Test
    void setPostOnly() {
        SecurityAuthcProperties props = new SecurityAuthcProperties();
        props.setPostOnly(false);
        assertThat(props.isPostOnly()).isFalse();
    }

    @Test
    void setUseForward() {
        SecurityAuthcProperties props = new SecurityAuthcProperties();
        props.setUseForward(true);
        assertThat(props.isUseForward()).isTrue();
    }

    @Test
    void setUseReferer() {
        SecurityAuthcProperties props = new SecurityAuthcProperties();
        props.setUseReferer(true);
        assertThat(props.isUseReferer()).isTrue();
    }
}
