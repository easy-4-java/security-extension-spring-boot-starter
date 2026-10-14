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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.utils.SecurityResponseUtils;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.util.CollectionUtils;

import java.io.IOException;
import java.util.List;

/**
 * Post Request Authentication Entry Point
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public class PostRequestAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

	protected Logger logger = LoggerFactory.getLogger(getClass());
	private List<MatchedAuthenticationEntryPoint> entryPoints;
	private boolean stateless = false;
	
	public PostRequestAuthenticationEntryPoint(String loginFormUrl, List<MatchedAuthenticationEntryPoint> entryPoints) {
		super(loginFormUrl);
		this.entryPoints = entryPoints;
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
			throws IOException, ServletException {
		/*
		 * if Rest request return 401 Unauthorized else rediect to specific page
		 */
		if (isStateless() || WebUtils.isPostRequest(request)) {
			
			if(CollectionUtils.isEmpty(entryPoints)) {
				SecurityResponseUtils.handleException(request, response, e);
			} else {
				
				boolean isMatched = false;
				for (MatchedAuthenticationEntryPoint entryPoint : entryPoints) {
					
					if(entryPoint != null && entryPoint.supports(e)) {
						entryPoint.commence(request, response, e);
						isMatched = true;
						break;
					}
					
				}
				if(!isMatched) {
					SecurityResponseUtils.handleException(request, response, e);
				}
			}
			
		} else {
			super.commence(request, response, e);
		}
	}
 

	public List<MatchedAuthenticationEntryPoint> getEntryPoints() {
		return entryPoints;
	}

	public boolean isStateless() {
		return stateless;
	}

	public void setEntryPoints(List<MatchedAuthenticationEntryPoint> entryPoints) {
		this.entryPoints = entryPoints;
	}

	public void setStateless(boolean stateless) {
		this.stateless = stateless;
	}
	
}