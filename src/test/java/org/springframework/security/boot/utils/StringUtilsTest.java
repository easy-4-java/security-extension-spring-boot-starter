package org.springframework.security.boot.utils;

import org.junit.jupiter.api.Test;
import org.springframework.security.boot.biz.utils.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link StringUtils}.
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
class StringUtilsTest {

    @Test
    void tokenizeToStringArrayWithComma() {
        String[] result = StringUtils.tokenizeToStringArray("a,b,c");
        assertThat(result).containsExactly("a", "b", "c");
    }

    @Test
    void tokenizeToStringArrayWithSemicolon() {
        String[] result = StringUtils.tokenizeToStringArray("a;b;c");
        assertThat(result).containsExactly("a", "b", "c");
    }

    @Test
    void tokenizeToStringArrayWithSpace() {
        String[] result = StringUtils.tokenizeToStringArray("a b c");
        assertThat(result).containsExactly("a", "b", "c");
    }

    @Test
    void tokenizeToStringArrayWithMixedDelimiters() {
        String[] result = StringUtils.tokenizeToStringArray("a,b;c d");
        assertThat(result).containsExactly("a", "b", "c", "d");
    }

    @Test
    void tokenizeToStringArrayWithEmptyString() {
        String[] result = StringUtils.tokenizeToStringArray("");
        assertThat(result).isEmpty();
    }

    @Test
    void tokenizeToStringArrayWithNull() {
        String[] result = StringUtils.tokenizeToStringArray(null);
        assertThat(result).isEmpty();
    }

    @Test
    void configLocationDelimiters() {
        assertThat(StringUtils.CONFIG_LOCATION_DELIMITERS).isEqualTo(",; \t\n");
    }
}
