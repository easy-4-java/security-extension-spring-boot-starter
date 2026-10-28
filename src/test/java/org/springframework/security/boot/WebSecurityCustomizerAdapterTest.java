package org.springframework.security.boot;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

class WebSecurityCustomizerAdapterTest {

    @Test
    void ipRuleChecksTheActualRequestAddress() {
        WebSecurityCustomizerAdapter adapter = new WebSecurityCustomizerAdapter(
                new SecurityBizProperties(), new SecuritySessionMgtProperties(), List.of()) {
        };
        WebExpressionAuthorizationManager manager =
                new WebExpressionAuthorizationManager("hasIpAddress('127.0.0.1')");
        manager.setExpressionHandler(adapter.customWebSecurityExpressionHandler());
        UsernamePasswordAuthenticationToken authentication =
                UsernamePasswordAuthenticationToken.authenticated("user", "", List.of());

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/protected");
        request.setRemoteAddr("127.0.0.1");
        assertTrue(manager.check(() -> authentication, new RequestAuthorizationContext(request)).isGranted());

        request.setRemoteAddr("10.0.0.1");
        assertFalse(manager.check(() -> authentication, new RequestAuthorizationContext(request)).isGranted());
    }
}
