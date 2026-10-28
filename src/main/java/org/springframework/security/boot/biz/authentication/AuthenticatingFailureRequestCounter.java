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
 * Authenticating Failure Counter On Request
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public class AuthenticatingFailureRequestCounter implements AuthenticatingFailureCounter {

    private String retryTimesKeyParameter = DEFAULT_RETRY_TIMES_KEY_PARAM_NAME;
    
	@Override
	public int get(ServletRequest request, ServletResponse response, String retryTimesKeyAttribute) {
		HttpServletRequest httpRequest = WebUtils.getNativeRequest(request, HttpServletRequest.class);
		String count = httpRequest.getParameter(getRetryTimesKeyParameter());
		if (null != count) {
			return Integer.parseInt(count);
		}
		return 0;
	}

	@Override
	public void increment(ServletRequest request, ServletResponse response, String retryTimesKeyAttribute) {
		// 参数方式传递错误次数,后端不进行计数累加
	}

	public String getRetryTimesKeyParameter() {
		return retryTimesKeyParameter;
	}

	public void setRetryTimesKeyParameter(String retryTimesKeyParameter) {
		this.retryTimesKeyParameter = retryTimesKeyParameter;
	}
	
}
