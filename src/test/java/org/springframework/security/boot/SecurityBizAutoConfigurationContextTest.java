package org.springframework.security.boot;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;
import org.springframework.web.servlet.LocaleResolver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SecurityBizAutoConfigurationContextTest {

    @Test
    void boot41CreatesServletSecurityBeans() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(SecurityBizAutoConfiguration.class))
                .withBean(LocaleResolver.class, AcceptHeaderLocaleResolver::new)
                .withPropertyValues("spring.security.session.failure-url=/expired")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(SessionRegistry.class);
                    assertThat(context).hasSingleBean(PasswordEncoder.class);
                    assertThat(context.getBean(SecuritySessionMgtProperties.class).getFailureUrl())
                            .isEqualTo("/expired");
                    assertThat(context).doesNotHaveBean(AuthenticationManager.class);
                });
    }

    @Test
    void createsAuthenticationManagerWhenProviderExists() {
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
