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
package org.springframework.security.boot.biz.authentication.nested;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.boot.utils.SecurityResponseUtils;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;

/**
 * TODO
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public interface MatchedAuthenticationEntryPoint {
	
	/**
	 * Whether it is supported
	 * @author <a href="https://github.com/loong10k">Loong Wan</a>
	 * @param e  the authentication exception
	 * @return true or false
	 */
	public boolean supports(AuthenticationException e) ;

	/**
	 * Commences an authentication scheme.
	 * <p>
	 * <code>ExceptionTranslationFilter</code> will populate the <code>HttpSession</code>
	 * attribute named
	 * <code>AbstractAuthenticationProcessingFilter.SPRING_SECURITY_SAVED_REQUEST_KEY</code>
	 * with the requested target URL before calling this method.
	 * <p>
	 * Implementations should modify the headers on the <code>ServletResponse</code> as
	 * necessary to commence the authentication process.
	 *
	 * @param request that resulted in an <code>AuthenticationException</code>
	 * @param response so that the user agent can begin authentication
	 * @param authException that caused the invocation
	 * @throws IOException IOException
	 * @throws ServletException ServletException
	 */
	default void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException{
		SecurityResponseUtils.handleException(request, response, authException);
	};
	
}
