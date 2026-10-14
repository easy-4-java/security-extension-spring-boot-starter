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
import org.springframework.security.core.Authentication;

import java.io.IOException;

/**
 * TODO
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public interface MatchedAuthenticationSuccessHandler {

	/**
	 * Whether it is supported
	 * @author <a href="https://github.com/loong10k">Loong Wan</a>
	 * @param authentication  the authentication
	 * @return true or false
	 */
	public boolean supports(Authentication authentication) ;
	
	/**
	 * Called when a user has been successfully authenticated.
	 *
	 * @param request the request which caused the successful authentication
	 * @param response the response
	 * @param authentication the &lt;tt&gt;Authentication&lt;/tt&gt; object which was created during
	 * the authentication process.
	 * @throws IOException IOException
	 * @throws ServletException ServletException
	 */
	default void onAuthenticationSuccess(HttpServletRequest request,
			HttpServletResponse response, Authentication authentication)
			throws IOException, ServletException {
		SecurityResponseUtils.handleSuccess(request, response, authentication);
	};
	
}
