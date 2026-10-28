package org.springframework.security.boot.utils;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.boot.biz.exception.AuthenticationCaptchaNotFoundException;
import org.springframework.security.boot.biz.utils.ReactiveSecurityResponseUtils;
import org.springframework.security.boot.biz.utils.ReactiveSubjectUtils;
import org.springframework.security.boot.biz.utils.WebfluxUtils;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Tests for WebfluxUtils, ReactiveSubjectUtils, and ReactiveSecurityResponseUtils.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class WebfluxAndReactiveTest {

    // --- WebfluxUtils ---

    @Test
    void webfluxIsPostRequestTrue() {
        ServerHttpRequest request = mock(ServerHttpRequest.class);
        when(request.getMethod()).thenReturn(HttpMethod.POST);
        assertThat(WebfluxUtils.isPostRequest(request)).isTrue();
    }

    @Test
    void webfluxIsPostRequestFalse() {
        ServerHttpRequest request = mock(ServerHttpRequest.class);
        when(request.getMethod()).thenReturn(HttpMethod.GET);
        assertThat(WebfluxUtils.isPostRequest(request)).isFalse();
    }

    @Test
    void webfluxIsAjaxRequestTrue() {
        ServerHttpRequest request = mock(ServerHttpRequest.class);
        HttpHeaders headers = new HttpHeaders();
        headers.add("X-Requested-With", "XMLHttpRequest");
        when(request.getHeaders()).thenReturn(headers);
        assertThat(WebfluxUtils.isAjaxRequest(request)).isTrue();
    }

    @Test
    void webfluxIsAjaxRequestFalse() {
        ServerHttpRequest request = mock(ServerHttpRequest.class);
        HttpHeaders headers = new HttpHeaders();
        when(request.getHeaders()).thenReturn(headers);
        assertThat(WebfluxUtils.isAjaxRequest(request)).isFalse();
    }

    @Test
    void webfluxIsContentTypeJsonTrue() {
        ServerHttpRequest request = mock(ServerHttpRequest.class);
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, "application/json");
        when(request.getHeaders()).thenReturn(headers);
        assertThat(WebfluxUtils.isContentTypeJson(request)).isTrue();
    }

    @Test
    void webfluxIsContentTypeJsonFalse() {
        ServerHttpRequest request = mock(ServerHttpRequest.class);
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, "text/html");
        when(request.getHeaders()).thenReturn(headers);
        assertThat(WebfluxUtils.isContentTypeJson(request)).isFalse();
    }

    @Test
    void webfluxIsObjectRequestTrue() {
        ServerHttpRequest request = mock(ServerHttpRequest.class);
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, "application/json");
        when(request.getHeaders()).thenReturn(headers);
        when(request.getMethod()).thenReturn(HttpMethod.POST);
        assertThat(WebfluxUtils.isObjectRequest(request)).isTrue();
    }

    @Test
    void webfluxIsObjectRequestFalse() {
        ServerHttpRequest request = mock(ServerHttpRequest.class);
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, "application/json");
        when(request.getHeaders()).thenReturn(headers);
        when(request.getMethod()).thenReturn(HttpMethod.GET);
        assertThat(WebfluxUtils.isObjectRequest(request)).isFalse();
    }

    @Test
    void webfluxIsAjaxResponseTrue() {
        ServerHttpRequest request = mock(ServerHttpRequest.class);
        when(request.getMethod()).thenReturn(HttpMethod.POST);
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, "text/html");
        when(request.getHeaders()).thenReturn(headers);
        assertThat(WebfluxUtils.isAjaxResponse(request)).isTrue();
    }

    @Test
    void webfluxIsAjaxResponseFalse() {
        ServerHttpRequest request = mock(ServerHttpRequest.class);
        when(request.getMethod()).thenReturn(HttpMethod.GET);
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, "text/html");
        headers.add("X-Requested-With", "other");
        when(request.getHeaders()).thenReturn(headers);
        assertThat(WebfluxUtils.isAjaxResponse(request)).isFalse();
    }

    @Test
    void webfluxHttpRequestPostTrue() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.getMethod()).thenReturn(HttpMethod.POST);
        assertThat(WebfluxUtils.isPostRequest(request)).isTrue();
    }

    @Test
    void webfluxHttpRequestPostFalse() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.getMethod()).thenReturn(HttpMethod.GET);
        assertThat(WebfluxUtils.isPostRequest(request)).isFalse();
    }

    @Test
    void webfluxHttpRequestAjaxRequest() {
        HttpRequest request = mock(HttpRequest.class);
        HttpHeaders headers = new HttpHeaders();
        headers.add("X-Requested-With", "XMLHttpRequest");
        when(request.getHeaders()).thenReturn(headers);
        assertThat(WebfluxUtils.isAjaxRequest(request)).isTrue();
    }

    @Test
    void webfluxHttpRequestContentTypeJson() {
        HttpRequest request = mock(HttpRequest.class);
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, "application/json");
        when(request.getHeaders()).thenReturn(headers);
        assertThat(WebfluxUtils.isContentTypeJson(request)).isTrue();
    }

    @Test
    void webfluxHttpRequestObjectRequest() {
        HttpRequest request = mock(HttpRequest.class);
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, "application/json");
        when(request.getHeaders()).thenReturn(headers);
        when(request.getMethod()).thenReturn(HttpMethod.POST);
        assertThat(WebfluxUtils.isObjectRequest(request)).isTrue();
    }

    // --- ReactiveSubjectUtils ---

    @Test
    void reactiveSubjectUtilsGetSecurityContext() {
        assertThat(ReactiveSubjectUtils.getSecurityContext()).isNotNull();
    }

    @Test
    void reactiveSubjectUtilsIsAssignableFromWithNull() {
        assertThat(ReactiveSubjectUtils.isAssignableFrom(null, String.class)).isFalse();
    }

    @Test
    void reactiveSubjectUtilsIsAssignableFromWithNullClasses() {
        assertThat(ReactiveSubjectUtils.isAssignableFrom(String.class, (Class<?>[]) null)).isFalse();
    }

    @Test
    void reactiveSubjectUtilsIsAssignableFromMatching() {
        assertThat(ReactiveSubjectUtils.isAssignableFrom(String.class, String.class)).isTrue();
    }

    @Test
    void reactiveSubjectUtilsIsAssignableFromSuperClass() {
        assertThat(ReactiveSubjectUtils.isAssignableFrom(String.class, Object.class)).isTrue();
    }

    @Test
    void reactiveSubjectUtilsIsAssignableFromNonMatching() {
        assertThat(ReactiveSubjectUtils.isAssignableFrom(String.class, Integer.class)).isFalse();
    }

    @Test
    void reactiveSubjectUtilsIsAssignableFromWithNullInClasses() {
        assertThat(ReactiveSubjectUtils.isAssignableFrom(String.class, null, Integer.class)).isFalse();
    }
}
