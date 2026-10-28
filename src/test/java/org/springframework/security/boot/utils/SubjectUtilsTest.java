package org.springframework.security.boot.utils;

import org.junit.jupiter.api.Test;
import org.springframework.security.boot.biz.utils.SubjectUtils;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for SubjectUtils.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class SubjectUtilsTest {

    @Test
    void toLongWithNull() {
        Long result = SubjectUtils.TO_LONG.apply(null);
        assertThat(result).isNull();
    }

    @Test
    void toLongWithLong() {
        Long result = SubjectUtils.TO_LONG.apply(42L);
        assertThat(result).isEqualTo(42L);
    }

    @Test
    void toLongWithString() {
        Long result = SubjectUtils.TO_LONG.apply("123");
        assertThat(result).isEqualTo(123L);
    }

    @Test
    void getSecurityContext() {
        assertThat(SubjectUtils.getSecurityContext()).isNotNull();
    }

    @Test
    void getAuthenticationReturnsNullWhenNotAuthenticated() {
        SecurityContextHolder.clearContext();
        assertThat(SubjectUtils.getAuthentication()).isNull();
    }

    @Test
    void getPrincipalReturnsNullWhenNotAuthenticated() {
        SecurityContextHolder.clearContext();
        assertThat(SubjectUtils.getPrincipal()).isNull();
    }

    @Test
    void isAuthenticatedReturnsFalseWhenNoAuth() {
        SecurityContextHolder.clearContext();
        assertThat(SubjectUtils.isAuthenticated()).isFalse();
    }

    @Test
    void isAuthenticatedWithAuth() {
        Authentication auth = new UsernamePasswordAuthenticationToken("user", "pass",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));
        assertThat(SubjectUtils.isAuthenticated(auth)).isTrue();
    }

    @Test
    void isAuthenticatedWithNull() {
        assertThat(SubjectUtils.isAuthenticated(null)).isFalse();
    }

    @Test
    void getPrincipalWithAuthentication() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(auth);
        Object result = SubjectUtils.getPrincipal();
        assertThat(result).isEqualTo(principal);
    }

    @Test
    void getPrincipalWithClass() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(auth);
        SecurityPrincipal result = SubjectUtils.getPrincipal(SecurityPrincipal.class);
        assertThat(result).isEqualTo(principal);
    }

    @Test
    void getPrincipalWithAuthenticationAndClass() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityPrincipal result = SubjectUtils.getPrincipal(auth, SecurityPrincipal.class);
        assertThat(result).isEqualTo(principal);
    }

    @Test
    void getPrincipalWithAuthenticationAndNonMatchingClass() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        String result = SubjectUtils.getPrincipal(auth, String.class);
        assertThat(result).isNull();
    }

    @Test
    void getUserIdWhenAuthenticated() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        principal.setUid("123");
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(auth);
        assertThat(SubjectUtils.getUserId()).isEqualTo("123");
    }

    @Test
    void getUserIdWhenNotAuthenticated() {
        SecurityContextHolder.clearContext();
        assertThat(SubjectUtils.getUserId()).isNull();
    }

    @Test
    void getUserIdLongWhenAuthenticated() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        principal.setUid("456");
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(auth);
        assertThat(SubjectUtils.getUserIdLong()).isEqualTo(456L);
    }

    @Test
    void getUserIdLongWhenNotAuthenticated() {
        SecurityContextHolder.clearContext();
        assertThat(SubjectUtils.getUserIdLong()).isNull();
    }

    @Test
    void getProfileStringWhenAuthenticated() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        Map<String, Object> profile = new HashMap<>();
        profile.put("email", "test@example.com");
        principal.setProfile(profile);
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(auth);
        assertThat(SubjectUtils.getProfileString("email")).isEqualTo("test@example.com");
    }

    @Test
    void getProfileStringWithDefaultWhenAuthenticated() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        principal.setProfile(new HashMap<>());
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(auth);
        assertThat(SubjectUtils.getProfileString("missing", "default")).isEqualTo("default");
    }

    @Test
    void getProfileStringWhenNotAuthenticated() {
        SecurityContextHolder.clearContext();
        assertThat(SubjectUtils.getProfileString("key")).isNull();
    }

    @Test
    void getProfileStringWithAuthentication() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        Map<String, Object> profile = new HashMap<>();
        profile.put("name", "test");
        principal.setProfile(profile);
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        assertThat(SubjectUtils.getProfileString(auth, "name")).isEqualTo("test");
    }

    @Test
    void getProfileStringWithAuthenticationAndDefault() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        principal.setProfile(new HashMap<>());
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        assertThat(SubjectUtils.getProfileString(auth, "missing", "def")).isEqualTo("def");
    }

    @Test
    void getProfileIntegerWhenAuthenticated() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        Map<String, Object> profile = new HashMap<>();
        profile.put("age", 25);
        principal.setProfile(profile);
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(auth);
        assertThat(SubjectUtils.getProfileInteger("age")).isEqualTo(25);
    }

    @Test
    void getProfileIntegerWithDefault() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        principal.setProfile(new HashMap<>());
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(auth);
        assertThat(SubjectUtils.getProfileInteger("missing", 0)).isEqualTo(0);
    }

    @Test
    void getProfileIntegerWhenNotAuthenticated() {
        SecurityContextHolder.clearContext();
        assertThat(SubjectUtils.getProfileInteger("key")).isNull();
    }

    @Test
    void getProfileIntegerWithAuthentication() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        Map<String, Object> profile = new HashMap<>();
        profile.put("age", 30);
        principal.setProfile(profile);
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        assertThat(SubjectUtils.getProfileInteger(auth, "age")).isEqualTo(30);
    }

    @Test
    void getProfileIntegerWithAuthenticationAndDefault() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        principal.setProfile(new HashMap<>());
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        assertThat(SubjectUtils.getProfileInteger(auth, "missing", 99)).isEqualTo(99);
    }

    @Test
    void getProfileLongWhenAuthenticated() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        Map<String, Object> profile = new HashMap<>();
        profile.put("id", 12345L);
        principal.setProfile(profile);
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(auth);
        assertThat(SubjectUtils.getProfileLong("id")).isEqualTo(12345L);
    }

    @Test
    void getProfileLongWithDefault() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        principal.setProfile(new HashMap<>());
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(auth);
        assertThat(SubjectUtils.getProfileLong("missing", 0L)).isEqualTo(0L);
    }

    @Test
    void getProfileLongWhenNotAuthenticated() {
        SecurityContextHolder.clearContext();
        assertThat(SubjectUtils.getProfileLong("key")).isNull();
    }

    @Test
    void getProfileLongWithAuthentication() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        Map<String, Object> profile = new HashMap<>();
        profile.put("id", 999L);
        principal.setProfile(profile);
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        assertThat(SubjectUtils.getProfileLong(auth, "id")).isEqualTo(999L);
    }

    @Test
    void getProfileLongWithAuthenticationAndDefault() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        principal.setProfile(new HashMap<>());
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        assertThat(SubjectUtils.getProfileLong(auth, "missing", 0L)).isEqualTo(0L);
    }

    @Test
    void getProfileDoubleWhenAuthenticated() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        Map<String, Object> profile = new HashMap<>();
        profile.put("score", 9.5);
        principal.setProfile(profile);
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(auth);
        assertThat(SubjectUtils.getProfileDouble("score")).isEqualTo(9.5);
    }

    @Test
    void getProfileDoubleWithDefault() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        principal.setProfile(new HashMap<>());
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(auth);
        assertThat(SubjectUtils.getProfileDouble("missing", 0.0)).isEqualTo(0.0);
    }

    @Test
    void getProfileDoubleWhenNotAuthenticated() {
        SecurityContextHolder.clearContext();
        assertThat(SubjectUtils.getProfileDouble("key")).isNull();
    }

    @Test
    void getProfileDoubleWithAuthentication() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        Map<String, Object> profile = new HashMap<>();
        profile.put("score", 8.8);
        principal.setProfile(profile);
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        assertThat(SubjectUtils.getProfileDouble(auth, "score")).isEqualTo(8.8);
    }

    @Test
    void getProfileDoubleWithAuthenticationAndDefault() {
        SecurityPrincipal principal = new SecurityPrincipal("user", "pass", "ROLE_ADMIN");
        principal.setProfile(new HashMap<>());
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, "pass",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        assertThat(SubjectUtils.getProfileDouble(auth, "missing", 1.1)).isEqualTo(1.1);
    }

    @Test
    void isAssignableFromWithNull() {
        assertThat(SubjectUtils.isAssignableFrom(null, String.class)).isFalse();
    }

    @Test
    void isAssignableFromWithNullClasses() {
        assertThat(SubjectUtils.isAssignableFrom(String.class, (Class<?>[]) null)).isFalse();
    }

    @Test
    void isAssignableFromWithMatchingClass() {
        assertThat(SubjectUtils.isAssignableFrom(String.class, String.class)).isTrue();
    }

    @Test
    void isAssignableFromWithSuperClass() {
        assertThat(SubjectUtils.isAssignableFrom(String.class, Object.class)).isTrue();
    }

    @Test
    void isAssignableFromWithNonMatchingClass() {
        assertThat(SubjectUtils.isAssignableFrom(String.class, Integer.class)).isFalse();
    }

    @Test
    void isAssignableFromWithNullInClasses() {
        assertThat(SubjectUtils.isAssignableFrom(String.class, null, Integer.class)).isFalse();
    }

    @Test
    void getRequestAttributes() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        ServletRequestAttributes attrs = new ServletRequestAttributes(request, response);
        RequestContextHolder.setRequestAttributes(attrs);
        assertThat(SubjectUtils.getRequestAttributes()).isNotNull();
    }

    @Test
    void getRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        ServletRequestAttributes attrs = new ServletRequestAttributes(request, response);
        RequestContextHolder.setRequestAttributes(attrs);
        assertThat(SubjectUtils.getRequest()).isNotNull();
    }

    @Test
    void getSession() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        ServletRequestAttributes attrs = new ServletRequestAttributes(request, response);
        RequestContextHolder.setRequestAttributes(attrs);
        assertThat(SubjectUtils.getSession(true)).isNotNull();
    }
}
