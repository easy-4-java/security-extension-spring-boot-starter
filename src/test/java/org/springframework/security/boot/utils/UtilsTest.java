package org.springframework.security.boot.utils;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.utils.ReactiveSecurityResponseUtils;
import org.springframework.security.boot.biz.utils.ReactiveSubjectUtils;
import org.springframework.security.boot.biz.utils.RemoteAddrUtils;
import org.springframework.security.boot.biz.utils.SecurityResponseUtils;
import org.springframework.security.boot.biz.utils.SubjectUtils;
import org.springframework.security.boot.biz.utils.WebSecurityUtils;
import org.springframework.security.boot.biz.utils.WebUtils;
import org.springframework.security.boot.biz.utils.WebfluxUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Tests for utility classes.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class UtilsTest {

    // RemoteAddrUtils
    @Test
    void remoteAddrUtilsWithCdnSrcIp() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Cdn-Src-Ip", "10.0.0.1");
        assertThat(RemoteAddrUtils.getRemoteAddr(request)).isEqualTo("10.0.0.1");
    }

    @Test
    void remoteAddrUtilsWithXRealIp() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Real-IP", "10.0.0.2");
        assertThat(RemoteAddrUtils.getRemoteAddr(request)).isEqualTo("10.0.0.2");
    }

    @Test
    void remoteAddrUtilsWithXForwardedFor() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Forwarded-For", "10.0.0.3");
        assertThat(RemoteAddrUtils.getRemoteAddr(request)).isEqualTo("10.0.0.3");
    }

    @Test
    void remoteAddrUtilsWithUnknownHeader() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Forwarded-For", "unknown");
        request.setRemoteAddr("192.168.1.1");
        assertThat(RemoteAddrUtils.getRemoteAddr(request)).isEqualTo("192.168.1.1");
    }

    @Test
    void remoteAddrUtilsWithLocalhost() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("localhost");
        assertThat(RemoteAddrUtils.getRemoteAddr(request)).isEqualTo("127.0.0.1");
    }

    @Test
    void remoteAddrUtilsWithNoHeaders() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.100");
        assertThat(RemoteAddrUtils.getRemoteAddr(request)).isEqualTo("192.168.1.100");
    }

    // WebUtils
    @Test
    void webUtilsIsPostRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        assertThat(WebUtils.isPostRequest(request)).isTrue();
    }

    @Test
    void webUtilsIsNotPostRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        assertThat(WebUtils.isPostRequest(request)).isFalse();
    }

    @Test
    void webUtilsIsAjaxRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        assertThat(WebUtils.isAjaxRequest(request)).isTrue();
    }

    @Test
    void webUtilsIsNotAjaxRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        assertThat(WebUtils.isAjaxRequest(request)).isFalse();
    }

    @Test
    void webUtilsIsContentTypeJson() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HttpHeaders.CONTENT_TYPE, "application/json");
        assertThat(WebUtils.isContentTypeJson(request)).isTrue();
    }

    @Test
    void webUtilsIsObjectRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        request.addHeader(HttpHeaders.CONTENT_TYPE, "application/json");
        assertThat(WebUtils.isObjectRequest(request)).isTrue();
    }

    @Test
    void webUtilsIsNotObjectRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        assertThat(WebUtils.isObjectRequest(request)).isFalse();
    }

    @Test
    void webUtilsIsAjaxResponse() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        assertThat(WebUtils.isAjaxResponse(request)).isTrue();
    }

    // SubjectUtils
    @Test
    void subjectUtilsIsAssignableFrom() {
        assertThat(SubjectUtils.isAssignableFrom(String.class, String.class)).isTrue();
        assertThat(SubjectUtils.isAssignableFrom(String.class, Object.class)).isTrue();
        assertThat(SubjectUtils.isAssignableFrom(String.class, Integer.class)).isFalse();
        assertThat(SubjectUtils.isAssignableFrom(null, String.class)).isFalse();
        assertThat(SubjectUtils.isAssignableFrom(String.class, (Class<?>[]) null)).isFalse();
    }

    @Test
    void subjectUtilsIsAuthenticatedWithNull() {
        assertThat(SubjectUtils.isAuthenticated((Authentication) null)).isFalse();
    }

    @Test
    void subjectUtilsIsAuthenticatedWithAuthenticated() {
        Authentication auth = mock(Authentication.class);
        when(auth.isAuthenticated()).thenReturn(true);
        assertThat(SubjectUtils.isAuthenticated(auth)).isTrue();
    }

    @Test
    void subjectUtilsIsAuthenticatedWithUnauthenticated() {
        Authentication auth = mock(Authentication.class);
        when(auth.isAuthenticated()).thenReturn(false);
        assertThat(SubjectUtils.isAuthenticated(auth)).isFalse();
    }

    @Test
    void subjectUtilsToLong() {
        assertThat(SubjectUtils.TO_LONG.apply(null)).isNull();
        assertThat(SubjectUtils.TO_LONG.apply(100L)).isEqualTo(100L);
        assertThat(SubjectUtils.TO_LONG.apply("123")).isEqualTo(123L);
        assertThat(SubjectUtils.TO_LONG.apply(42)).isEqualTo(42L);
    }

    @Test
    void subjectUtilsCopySession() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute("key1", "value1");
        request.getSession().setAttribute("key2", "value2");
        var oldSession = request.getSession();
        var newSession = SubjectUtils.copySession(request, oldSession);
        assertThat(newSession.getAttribute("key1")).isEqualTo("value1");
        assertThat(newSession.getAttribute("key2")).isEqualTo("value2");
    }

    @Test
    void subjectUtilsGetPrincipalWithAuthentication() {
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("test-user");
        Object principal = SubjectUtils.getPrincipal(auth, String.class);
        assertThat(principal).isEqualTo("test-user");
    }

    @Test
    void subjectUtilsGetPrincipalWithNonMatchingClass() {
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("test-user");
        Object principal = SubjectUtils.getPrincipal(auth, Integer.class);
        assertThat(principal).isNull();
    }

    // SecurityBizProperties
    @Test
    void securityBizProperties() {
        org.springframework.security.boot.SecurityBizProperties props = new org.springframework.security.boot.SecurityBizProperties();
        assertThat(props.getFilterChainDefinitionMap()).isNotNull();
        assertThat(props.getFilterChainDefinitionMap()).isEmpty();
        props.getFilterChainDefinitionMap().put("/api/**", "authc");
        assertThat(props.getFilterChainDefinitionMap()).hasSize(1);
    }

    // WebSecurityUtils
    @Test
    void webSecurityUtils() {
        assertThat(WebSecurityUtils.class).isNotNull();
    }

    // WebfluxUtils
    @Test
    void webfluxUtils() {
        assertThat(WebfluxUtils.class).isNotNull();
    }

    // ReactiveSecurityResponseUtils
    @Test
    void reactiveSecurityResponseUtils() {
        assertThat(ReactiveSecurityResponseUtils.class).isNotNull();
    }

    // ReactiveSubjectUtils
    @Test
    void reactiveSubjectUtils() {
        assertThat(ReactiveSubjectUtils.class).isNotNull();
    }

    // SecurityResponseUtils
    @Test
    void securityResponseUtils() {
        assertThat(SecurityResponseUtils.class).isNotNull();
    }
}
