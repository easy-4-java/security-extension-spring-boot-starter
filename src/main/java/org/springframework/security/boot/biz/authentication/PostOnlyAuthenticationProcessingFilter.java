package org.springframework.security.boot.biz.authentication;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationMethodNotSupportedException;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.IOException;

/**
 * PostOnly Authentication Processing Filter
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public abstract class PostOnlyAuthenticationProcessingFilter extends AuthenticationProcessingFilter {

	// ~ Static fields/initializers
	// =====================================================================================
	
	protected static Logger logger = LoggerFactory.getLogger(PostOnlyAuthenticationProcessingFilter.class);
	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	private boolean postOnly = true;
	
	// ~ Constructors
	// ===================================================================================================
	
	/**
	 * @param defaultFilterProcessesUrl the default value for &lt;tt&gt;filterProcessesUrl&lt;/tt&gt;.
	 */
	protected PostOnlyAuthenticationProcessingFilter(String defaultFilterProcessesUrl) {
		super(defaultFilterProcessesUrl);
	}

	/**
	 * Creates a new instance
	 *
	 * @param requiresAuthenticationRequestMatcher the {@link RequestMatcher} used to
	 * determine if authentication is required. Cannot be null.
	 */
	protected PostOnlyAuthenticationProcessingFilter(
			RequestMatcher requiresAuthenticationRequestMatcher) {
		super(requiresAuthenticationRequestMatcher);
	}

	// ~ Methods
	// ========================================================================================================

	@Override
	public final Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		if (isPostOnly() && !WebUtils.isPostRequest(request) ) {
			if (logger.isDebugEnabled()) {
				logger.debug("Authentication method not supported. Request method: " + request.getMethod());
			}
			throw new AuthenticationMethodNotSupportedException(messages.getMessage(AuthResponseCode.SC_AUTHC_METHOD_NOT_ALLOWED.getMsgKey(), new Object[] { request.getMethod() }, 
					"Authentication method not supported. Request method:" + request.getMethod()));
		}
		
		// Set RequestContextHolder
		ServletRequestAttributes requestAttributes = new ServletRequestAttributes(request, response);
		RequestContextHolder.setRequestAttributes(requestAttributes, true);
		
		// real method
		return this.doAttemptAuthentication(request, response);

	}
	
	/**
	 * Defines whether only HTTP POST requests will be allowed by this filter. If set to
	 * true, and an authentication request is received which is not a POST request, an
	 * exception will be raised immediately and authentication will not be attempted. The
	 * &lt;tt&gt;unsuccessfulAuthentication()&lt;/tt&gt; method will be called as if handling a failed
	 * authentication.
	 * <p>
	 * Defaults to &lt;tt&gt;true&lt;/tt&gt; but may be overridden by subclasses.
	 * @param postOnly if postOnly
	 */
	public void setPostOnly(boolean postOnly) {
		this.postOnly = postOnly;
	}
	
	public boolean isPostOnly() {
		return postOnly;
	}

}
