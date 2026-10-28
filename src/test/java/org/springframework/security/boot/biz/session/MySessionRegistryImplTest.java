package org.springframework.security.boot.biz.session;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MySessionRegistryImplTest {

    @Test
    void registersAndRemovesUserDetailsSession() {
        MySessionRegistryImpl registry = new MySessionRegistryImpl();
        UserDetails principal = User.withUsername("alice").password("secret").roles("USER").build();

        registry.registerNewSession("session-1", principal);

        assertThat(registry.getSessionInformation("session-1")).isNotNull();
        assertThat(registry.getAllSessions(principal, false)).hasSize(1);
        assertThat(registry.getAllPrincipals()).containsExactly(principal);

        registry.removeSessionInformation("session-1");

        assertThat(registry.getSessionInformation("session-1")).isNull();
        assertThat(registry.getAllSessions(principal, false)).isEmpty();
        assertThat(registry.getAllPrincipals()).isEmpty();
    }

    @Test
    void supportsStringPrincipalAndRefreshesStoredSession() throws InterruptedException {
        MySessionRegistryImpl registry = new MySessionRegistryImpl();
        registry.registerNewSession("session-2", "bob");
        SessionInformation info = registry.getSessionInformation("session-2");
        long previousRequest = info.getLastRequest().getTime();

        Thread.sleep(5);
        registry.refreshLastRequest("session-2");

        assertThat(registry.getSessionInformation("session-2").getLastRequest().getTime())
                .isGreaterThan(previousRequest);
        info.expireNow();
        assertThat(registry.getAllSessions("bob", false)).isEmpty();
        assertThat(registry.getAllSessions("bob", true)).hasSize(1);
    }

    @Test
    void destroyedEventRemovesOnlyItsSession() {
        MySessionRegistryImpl registry = new MySessionRegistryImpl();
        registry.registerNewSession("first", "carol");
        registry.registerNewSession("second", "carol");
        SessionDestroyedEvent event = mock(SessionDestroyedEvent.class);
        when(event.getId()).thenReturn("first");

        registry.onApplicationEvent(event);

        assertThat(registry.getSessionInformation("first")).isNull();
        assertThat(registry.getAllSessions("carol", false)).hasSize(1);
        assertThat(registry.getAllPrincipals()).containsExactly("carol");
    }
}
