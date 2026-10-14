package org.springframework.security.boot.biz;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.io.IOException;
import java.util.List;

/**
 * 认证请求失败后的处理实现
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public class ListenedAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
	
	private List<AuthenticationListener> authenticationListeners;
	
	public ListenedAuthenticationFailureHandler(String defaultFailureUrl) {
		this.setDefaultFailureUrl(defaultFailureUrl);
	}
	
	public ListenedAuthenticationFailureHandler(List<AuthenticationListener> authenticationListeners, String defaultFailureUrl) {
		this.setAuthenticationListeners(authenticationListeners);
		this.setDefaultFailureUrl(defaultFailureUrl);
	}
	
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException, ServletException {

		//调用事件监听器
		if(getAuthenticationListeners() != null && getAuthenticationListeners().size() > 0){
			for (AuthenticationListener authenticationListener : getAuthenticationListeners()) {
				authenticationListener.onFailure(request, response, e);
			}
		}
		 
		super.onAuthenticationFailure(request, response, e);
		
	}
	
	public List<AuthenticationListener> getAuthenticationListeners() {
		return authenticationListeners;
	}

	public void setAuthenticationListeners(List<AuthenticationListener> authenticationListeners) {
		this.authenticationListeners = authenticationListeners;
	}

}
