package org.springframework.security.boot;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.extension.web.servlet.i18n.LocaleContextFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SecurityBizAutoConfigurationContextTest {

    @Test
    void boot23CreatesServletSecurityBeansWithSpringExtension2() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(SecurityBizAutoConfiguration.class))
                .withBean(LocaleResolver.class, AcceptHeaderLocaleResolver::new)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(SessionRegistry.class);
                    assertThat(context).hasSingleBean(PasswordEncoder.class);
                    assertThat(context).hasSingleBean(LocaleContextFilter.class);
                    assertThat(context).doesNotHaveBean(AuthenticationManager.class);
                });
    }

    @Test
    void boot23CreatesAuthenticationManagerWhenProviderExists() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(SecurityBizAutoConfiguration.class))
                .withBean(LocaleResolver.class, AcceptHeaderLocaleResolver::new)
                .withBean(AuthenticationProvider.class, () -> mock(AuthenticationProvider.class))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(AuthenticationManager.class);
                });
    }
}
