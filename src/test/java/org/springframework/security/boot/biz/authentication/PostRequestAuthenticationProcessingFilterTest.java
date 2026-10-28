package org.springframework.security.boot.biz.authentication;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class PostRequestAuthenticationProcessingFilterTest {

    @Test
    void defaultMatcherOnlySelectsLoginPath() {
        TestFilter filter = new TestFilter();

        MockHttpServletRequest login = new MockHttpServletRequest("POST", "/login");
        login.setServletPath("/login");
        MockHttpServletRequest other = new MockHttpServletRequest("POST", "/other");
        other.setServletPath("/other");

        assertTrue(filter.matches(login));
        assertFalse(filter.matches(other));
    }

    private static final class TestFilter extends PostRequestAuthenticationProcessingFilter {

        private TestFilter() {
            super(new ObjectMapper());
        }

        private boolean matches(MockHttpServletRequest request) {
            return requiresAuthentication(request, new MockHttpServletResponse());
        }
    }
}
