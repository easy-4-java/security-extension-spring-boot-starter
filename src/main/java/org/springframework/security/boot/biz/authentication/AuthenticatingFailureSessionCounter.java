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
package org.springframework.security.boot.biz.authentication;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.util.WebUtils;

/**
 * Authenticating Failure Counter On Session 
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public class AuthenticatingFailureSessionCounter implements AuthenticatingFailureCounter {

	@Override
	public int get(ServletRequest request, ServletResponse response, String retryTimesKeyAttribute) {
		HttpServletRequest httpRequest = WebUtils.getNativeRequest(request, HttpServletRequest.class);
		Object count = WebUtils.getSessionAttribute(httpRequest, retryTimesKeyAttribute);
		if (null != count) {
			return Integer.parseInt(String.valueOf(count));
		}
		return 0;
	}

	@Override
	public void increment(ServletRequest request, ServletResponse response, String retryTimesKeyAttribute) {
		HttpServletRequest httpRequest = WebUtils.getNativeRequest(request, HttpServletRequest.class);
		Object count = WebUtils.getSessionAttribute(httpRequest, retryTimesKeyAttribute);
		if (null == count) {
			WebUtils.setSessionAttribute(httpRequest, retryTimesKeyAttribute, 1);
		} else {
			WebUtils.setSessionAttribute(httpRequest, retryTimesKeyAttribute,
					Long.parseLong(String.valueOf(count)) + 1);
		}
	}

}
