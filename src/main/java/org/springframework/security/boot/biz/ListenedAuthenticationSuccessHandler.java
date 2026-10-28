package org.springframework.security.boot.biz;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import java.io.IOException;
import java.util.List;

/**
 * 认证请求成功后的处理实现
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public class ListenedAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
	
	private List<AuthenticationListener> authenticationListeners;
	
	public ListenedAuthenticationSuccessHandler(String defaultTargetUrl) {
		this.setDefaultTargetUrl(defaultTargetUrl);
	}
	
	public ListenedAuthenticationSuccessHandler(List<AuthenticationListener> authenticationListeners, String defaultTargetUrl) {
		this.setAuthenticationListeners(authenticationListeners);
		this.setDefaultTargetUrl(defaultTargetUrl);
	}
	
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		
		//调用事件监听器
		if(getAuthenticationListeners() != null && getAuthenticationListeners().size() > 0){
			for (AuthenticationListener authenticationListener : getAuthenticationListeners()) {
				authenticationListener.onSuccess(request, response, authentication);
			}
		}
	 	 
		super.onAuthenticationSuccess(request, response, authentication);

	}

	public List<AuthenticationListener> getAuthenticationListeners() {
		return authenticationListeners;
	}

	public void setAuthenticationListeners(List<AuthenticationListener> authenticationListeners) {
		this.authenticationListeners = authenticationListeners;
	}

}
