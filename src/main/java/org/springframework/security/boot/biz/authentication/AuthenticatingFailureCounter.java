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

/**
 * Authenticating Failure Counter
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public interface AuthenticatingFailureCounter {

	public static final String DEFAULT_RETRY_TIMES_KEY_PARAM_NAME = "failureRetries";

	/**
	 * 
	 * Get The Failure Counter
	 * @author <a href="https://github.com/loong10k">Loong Wan</a>
	 * @param request ServletRequest
	 * @param response ServletResponse
	 * @param retryTimesKeyAttribute The retryTimes Key Attribute
	 * @return the error count
	 */
	int get(ServletRequest request, ServletResponse response, String retryTimesKeyAttribute);
	
	/**
	 * 
	 * Failure Counter increment
	 * @author <a href="https://github.com/loong10k">Loong Wan</a>
	 * @param request ServletRequest
	 * @param response ServletResponse
	 * @param retryTimesKeyAttribute The retryTimes Key Attribute
	 */
	void increment(ServletRequest request, ServletResponse response, String retryTimesKeyAttribute);
	
}
