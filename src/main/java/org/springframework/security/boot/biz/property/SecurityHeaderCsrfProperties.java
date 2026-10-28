/*
 * Copyright (c) 2018, hiwepy (https://github.com/easy-4-java).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.biz.property;

import javax.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Security Header Csrf Properties
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@Getter
@Setter
@ToString
public class SecurityHeaderCsrfProperties {

	/**
	 * Enable Security Csrf.
	 */
	private boolean enabled = false;
	/**
	 * <p>
	 * Allows specifying {@link HttpServletRequest} that should not use CSRF Protection
	 * even if they match the {@link #requireCsrfProtectionMatcher(RequestMatcher)}.
	 * </p>
	 *
	 * <p>
	 * For example, the following configuration will ensure CSRF protection ignores:
	 * </p>
	 * <ul>
	 * <li>Any GET, HEAD, TRACE, OPTIONS (this is the default)</li>
	 * <li>We also explicitly state to ignore any request that starts with "/sockjs/"</li>
	 * </ul>
	 *
	 * <pre>
	 * http
	 *     .csrf()
	 *         .ignoringAntMatchers("/sockjs/**")
	 *         .and()
	 *     ...
	 * </pre>
	 *
	 */
	private String ignoringAntMatchers;
	
	/**
	 * Specify the {@link RequestMatcher} to use for determining when CSRF should be
	 * applied. The default is to ignore GET, HEAD, TRACE, OPTIONS and process all other
	 * requests.
	 *
	 */
	private String requireCsrfAntMatchers;
	
	
}
