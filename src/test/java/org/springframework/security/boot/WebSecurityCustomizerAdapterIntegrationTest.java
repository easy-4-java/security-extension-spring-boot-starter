package org.springframework.security.boot;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Exercises adapter URL rules through a Spring Security filter chain. */
class WebSecurityCustomizerAdapterIntegrationTest {

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void roleRuleAllowsMatchingRoleAndRejectsOtherUsers() {
        assertRule("roles[admin]", "ROLE_admin", "ROLE_user");
    }

    @Test
    void multipleRolesAcceptEitherRoleAndRejectUnlistedRole() {
        assertRule("roles[admin,editor,reviewer]", "ROLE_reviewer", "ROLE_user");
    }

    @Test
    void singlePermissionAllowsMatchingAuthorityAndRejectsOtherUsers() {
        assertRule("perms[user:read]", "user:read", "user:write");
    }

    @Test
    void multiplePermissionsAcceptEitherAuthorityAndRejectUnlistedAuthority() {
        assertRule("perms[user:read,user:write,user:delete]", "user:delete", "user:archive");
    }

    @Test
    void ipRuleAllowsMatchingSubnetAndRejectsOtherAddresses() {
        SecurityBizProperties properties = new SecurityBizProperties();
        properties.setFilterChainDefinitionMap(new LinkedHashMap<>(Map.of("/internal", "ipaddr[192.168.1.0/24]")));

        new WebApplicationContextRunner()
            .withUserConfiguration(RulesConfiguration.class)
            .withBean(SecurityBizProperties.class, () -> properties)
            .run(context -> {
                assertThat(context).hasNotFailed();
                AuthorizationFilter filter = authorizationFilter(context.getBean(SecurityFilterChain.class));
                SecurityContextHolder.getContext().setAuthentication(authenticated("ROLE_user"));
                assertDoesNotThrow(() -> authorize(filter, "/internal", "192.168.1.42"));
                assertThrows(AccessDeniedException.class,
                    () -> authorize(filter, "/internal", "192.168.2.42"));
            });
    }

    private static void assertRule(String rule, String allowedAuthority, String deniedAuthority) {
        SecurityBizProperties properties = new SecurityBizProperties();
        properties.setFilterChainDefinitionMap(new LinkedHashMap<>(Map.of("/admin", rule)));

        new WebApplicationContextRunner()
            .withUserConfiguration(RulesConfiguration.class)
            .withBean(SecurityBizProperties.class, () -> properties)
            .run(context -> {
                assertThat(context).hasNotFailed();
                AuthorizationFilter filter = authorizationFilter(context.getBean(SecurityFilterChain.class));

                SecurityContextHolder.getContext().setAuthentication(authenticated(allowedAuthority));
                assertDoesNotThrow(() -> authorize(filter, "/admin"));
                SecurityContextHolder.getContext().setAuthentication(authenticated(deniedAuthority));
                assertThrows(AccessDeniedException.class, () -> authorize(filter, "/admin"));
            });
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity
    static class RulesConfiguration {
        @Bean
        SecurityFilterChain securityFilterChain(HttpSecurity http, SecurityBizProperties properties) throws Exception {
            WebSecurityCustomizerAdapter adapter = new WebSecurityCustomizerAdapter(
                properties, new SecuritySessionMgtProperties(), List.of()) { };
            adapter.configure(http);
            return http.build();
        }
    }

    private static UsernamePasswordAuthenticationToken authenticated(String authority) {
        return UsernamePasswordAuthenticationToken.authenticated(
            "user", "credential", List.of(new SimpleGrantedAuthority(authority)));
    }

    private static AuthorizationFilter authorizationFilter(SecurityFilterChain chain) {
        return chain.getFilters().stream()
            .filter(AuthorizationFilter.class::isInstance)
            .map(AuthorizationFilter.class::cast)
            .findFirst().orElseThrow(() -> new AssertionError(chain.getFilters().toString()));
    }

    private static void authorize(AuthorizationFilter filter, String path) throws Exception {
        authorize(filter, path, "127.0.0.1");
    }

    private static void authorize(AuthorizationFilter filter, String path, String remoteAddress) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setServletPath(path);
        request.setRemoteAddr(remoteAddress);
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
    }
}
