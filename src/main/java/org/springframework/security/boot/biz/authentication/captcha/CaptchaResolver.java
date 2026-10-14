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
package org.springframework.security.boot.biz.authentication.captcha;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.Date;

/**
 * Captcha Resolver
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public interface CaptchaResolver {

	/**
	 * Valid the current captcha via the given request.
	 * @param request request to be used for resolution
	 * @param capText the captcha value
	 * @return the result
	 */
	boolean validCaptcha(HttpServletRequest request, String capText);

	/**
	 * Set the current captcha to the given one.
	 * @param request request to be used for captcha modification
	 * @param response response to be used for captcha modification
	 * @param capText the new captcha value
	 * @param capDate the captcha create time
	 */
	void setCaptcha(HttpServletRequest request, HttpServletResponse response, String capText, Date capDate);
	
}
