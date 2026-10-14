package org.springframework.security.boot.biz.authentication;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.utils.SecurityResponseUtils;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.ExceptionMappingAuthenticationFailureHandler;
import org.springframework.util.CollectionUtils;

import java.io.IOException;
import java.util.List;

/**
 * Post Request Authentication Failure Handler
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public class PostRequestAuthenticationFailureHandler extends ExceptionMappingAuthenticationFailureHandler {

	protected Logger logger = LoggerFactory.getLogger(getClass());
	private List<AuthenticationListener> authenticationListeners;
	private List<MatchedAuthenticationFailureHandler> failureHandlers;
	private boolean stateless = false;
	
	public PostRequestAuthenticationFailureHandler(List<MatchedAuthenticationFailureHandler> failureHandlers) {
		this.setFailureHandlers(failureHandlers);
	}

	public PostRequestAuthenticationFailureHandler(List<AuthenticationListener> authenticationListeners,
			List<MatchedAuthenticationFailureHandler> failureHandlers) {
		this.setAuthenticationListeners(authenticationListeners);
		this.setFailureHandlers(failureHandlers);
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException, ServletException {

		// 调用事件监听器
		if (getAuthenticationListeners() != null && getAuthenticationListeners().size() > 0) {
			for (AuthenticationListener authenticationListener : getAuthenticationListeners()) {
				authenticationListener.onFailure(request, response, e);
			}
		}

		/*
		 * if Rest request return json else rediect to specific page
		 */
		if (isStateless() || WebUtils.isPostRequest(request)) {
			
			if(CollectionUtils.isEmpty(failureHandlers)) {
				SecurityResponseUtils.handleException(request, response, e);
			} else {
				
				boolean isMatched = false;
				for (MatchedAuthenticationFailureHandler failureHandler : failureHandlers) {
					
					if(failureHandler != null && failureHandler.supports(e)) {
						failureHandler.onAuthenticationFailure(request, response, e);
						isMatched = true;
						break;
					}
					
				}
				if(!isMatched) {
					SecurityResponseUtils.handleException(request, response, e);
				}
			}
			
		} else {
			super.onAuthenticationFailure(request, response, e);
		}

	}
 
	
	public List<AuthenticationListener> getAuthenticationListeners() {
		return authenticationListeners;
	}

	public void setAuthenticationListeners(List<AuthenticationListener> authenticationListeners) {
		this.authenticationListeners = authenticationListeners;
	}

	public List<MatchedAuthenticationFailureHandler> getFailureHandlers() {
		return failureHandlers;
	}

	public void setFailureHandlers(List<MatchedAuthenticationFailureHandler> failureHandlers) {
		this.failureHandlers = failureHandlers;
	}

	public boolean isStateless() {
		return stateless;
	}

	public void setStateless(boolean stateless) {
		this.stateless = stateless;
	}

}