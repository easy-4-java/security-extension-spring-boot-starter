package org.springframework.security.boot.utils;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.security.boot.biz.utils.SecurityResponseUtils;
import org.springframework.security.boot.biz.utils.WebUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.*;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationCaptchaNotFoundException;
import org.springframework.security.boot.biz.exception.AuthenticationServiceExceptionAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for WebUtils, SecurityResponseUtils, and related utility classes.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class WebUtilsAndSecurityResponseTest {

    // --- WebUtils ---

    @Test
    void webUtilsIsPostRequestTrue() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        assertThat(WebUtils.isPostRequest(request)).isTrue();
    }

    @Test
    void webUtilsIsPostRequestFalse() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        assertThat(WebUtils.isPostRequest(request)).isFalse();
    }

    @Test
    void webUtilsIsAjaxRequestTrue() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        assertThat(WebUtils.isAjaxRequest(request)).isTrue();
    }

    @Test
    void webUtilsIsAjaxRequestFalse() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        assertThat(WebUtils.isAjaxRequest(request)).isFalse();
    }

    @Test
    void webUtilsIsContentTypeJsonTrue() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HttpHeaders.CONTENT_TYPE, "application/json");
        assertThat(WebUtils.isContentTypeJson(request)).isTrue();
    }

    @Test
    void webUtilsIsContentTypeJsonFalse() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HttpHeaders.CONTENT_TYPE, "text/html");
        assertThat(WebUtils.isContentTypeJson(request)).isFalse();
    }

    @Test
    void webUtilsIsObjectRequestTrue() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        request.addHeader(HttpHeaders.CONTENT_TYPE, "application/json");
        assertThat(WebUtils.isObjectRequest(request)).isTrue();
    }

    @Test
    void webUtilsIsObjectRequestFalse() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        request.addHeader(HttpHeaders.CONTENT_TYPE, "application/json");
        assertThat(WebUtils.isObjectRequest(request)).isFalse();
    }

    @Test
    void webUtilsIsAjaxResponseTrue() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        request.addHeader(HttpHeaders.CONTENT_TYPE, "text/html");
        assertThat(WebUtils.isAjaxResponse(request)).isTrue();
    }

    @Test
    void webUtilsIsAjaxResponseFalse() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        request.addHeader(HttpHeaders.CONTENT_TYPE, "text/html");
        request.addHeader("X-Requested-With", "other");
        assertThat(WebUtils.isAjaxResponse(request)).isFalse();
    }

    // --- SecurityResponseUtils ---

    @Test
    void securityResponseUtilsHandleSuccess() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        org.springframework.security.core.Authentication auth = org.mockito.Mockito.mock(org.springframework.security.core.Authentication.class);
        SecurityResponseUtils.handleSuccess(request, response, auth);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentAsString()).contains("success");
    }

    @Test
    void securityResponseUtilsHandleExceptionBadCredentials() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        SecurityResponseUtils.handleException(request, response, new BadCredentialsException("bad"));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentAsString()).isNotEmpty();
    }

    @Test
    void securityResponseUtilsHandleExceptionUsernameNotFound() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        SecurityResponseUtils.handleException(request, response, new UsernameNotFoundException("not found"));
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void securityResponseUtilsHandleExceptionDisabled() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        SecurityResponseUtils.handleException(request, response, new DisabledException("disabled"));
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void securityResponseUtilsHandleExceptionLocked() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        SecurityResponseUtils.handleException(request, response, new LockedException("locked"));
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void securityResponseUtilsHandleExceptionAccountExpired() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        SecurityResponseUtils.handleException(request, response, new AccountExpiredException("expired"));
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void securityResponseUtilsHandleExceptionCredentialsExpired() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        SecurityResponseUtils.handleException(request, response, new CredentialsExpiredException("expired"));
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void securityResponseUtilsHandleExceptionGeneric() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        SecurityResponseUtils.handleException(request, response, new AuthenticationException("generic") {});
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void securityResponseUtilsHandleExceptionAdapter() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationException ex = new AuthenticationCaptchaNotFoundException("captcha required");
        SecurityResponseUtils.handleException(request, response, ex);
        assertThat(response.getStatus()).isEqualTo(200);
    }
}
