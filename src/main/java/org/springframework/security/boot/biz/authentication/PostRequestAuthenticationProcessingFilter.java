package org.springframework.security.boot.biz.authentication;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationCaptchaIncorrectException;
import org.springframework.security.boot.biz.exception.AuthenticationCaptchaNotFoundException;
import org.springframework.security.boot.biz.exception.AuthenticationOverRetryRemindException;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.io.IOException;

/**
 * 
 * 账号、密码、验证码认证过滤器
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public class PostRequestAuthenticationProcessingFilter extends PostOnlyAuthenticationProcessingFilter {

	// ~ Static fields/initializers
	// =====================================================================================
	
	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	
	public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "username";
	public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "password";
	public static final String SPRING_SECURITY_FORM_CAPTCHA_KEY = "captcha";
	public static final String DEFAULT_RETRY_TIMES_KEY_ATTRIBUTE_NAME = "securityLoginFailureRetries";
	
	private String usernameParameter = SPRING_SECURITY_FORM_USERNAME_KEY;
	private String passwordParameter = SPRING_SECURITY_FORM_PASSWORD_KEY;
	private boolean captchaRequired = false;
	private String captchaParameter = SPRING_SECURITY_FORM_CAPTCHA_KEY;
	private CaptchaResolver captchaResolver;
	private boolean postOnly = true;
	private String retryTimesKeyAttribute = DEFAULT_RETRY_TIMES_KEY_ATTRIBUTE_NAME;
	/** Maximum number of retry to login . */
	private int retryTimesWhenAccessDenied = 3;
	
	private ObjectMapper objectMapper = new ObjectMapper();
	private AuthenticatingFailureCounter failureCounter;
	
	// ~ Constructors
	// ===================================================================================================
	
	public PostRequestAuthenticationProcessingFilter(ObjectMapper objectMapper) {
		super(new AntPathRequestMatcher("/login"));
		this.objectMapper = objectMapper;
	}

	public PostRequestAuthenticationProcessingFilter(ObjectMapper objectMapper, RequestMatcher requestMatcher) {
		super(requestMatcher);
		this.objectMapper = objectMapper;
	}

	// ~ Methods
	// ========================================================================================================
	
	@Override
	public Authentication doAttemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {

		try {

			AbstractAuthenticationToken authRequest = null;
			// Post && JSON
			if(WebUtils.isObjectRequest(request)) {
				
				PostLoginRequest loginRequest = objectMapper.readValue(request.getReader(), PostLoginRequest.class);
				
				// The retry limit has been exceeded and a reminder is required
		        if(isOverRetryRemind(request, response)) {
		        	throw new AuthenticationOverRetryRemindException(messages.getMessage(AuthResponseCode.SC_AUTHC_OVER_RETRY_REMIND.getMsgKey(),
		        			"The number of login errors exceeds the maximum retry limit and a verification code is required."));
		        }
		        
		        // 验证码必填或者错误次数超出系统限制，则要求填入验证码
		 		if(isCaptchaRequired() || isOverRetryTimes(request, response)) {
		 			
		 			if(!StringUtils.hasText(loginRequest.getCaptcha())) {
						throw new AuthenticationCaptchaNotFoundException(messages.getMessage(AuthResponseCode.SC_AUTHC_CAPTCHA_REQUIRED.getMsgKey(), 
								"Captcha not provided"));
					}  
		 	        // 进行验证	
	 	        	boolean validation = captchaResolver.validCaptcha(request, loginRequest.getCaptcha());
					if (!validation) {
						throw new AuthenticationCaptchaIncorrectException(messages.getMessage(AuthResponseCode.SC_AUTHC_CAPTCHA_INCORRECT.getMsgKey(), 
								"Captcha was incorrect."));
					}
					
				}
		 		
		 		authRequest = this.authenticationToken( loginRequest.getUsername(), loginRequest.getPassword());

			} else {
				
				// The retry limit has been exceeded and a reminder is required
		        if(isOverRetryRemind(request, response)) {
		        	throw new AuthenticationOverRetryRemindException(messages.getMessage(AuthResponseCode.SC_AUTHC_OVER_RETRY_REMIND.getMsgKey(),
		        			"The number of login errors exceeds the maximum retry limit and a verification code is required."));
		        }
		        // 验证码必填或者错误次数超出系统限制，则要求填入验证码
		 		if(isCaptchaRequired() || isOverRetryTimes(request, response)) {
		 			
		 			String captcha = obtainCaptcha(request);
		 			if(!StringUtils.hasText(captcha)) {
						throw new AuthenticationCaptchaNotFoundException(messages.getMessage(AuthResponseCode.SC_AUTHC_CAPTCHA_REQUIRED.getMsgKey(), 
								"Captcha not provided."));
					}  
		 	        // 进行验证	
	 	        	boolean validation = captchaResolver.validCaptcha(request, captcha);
					if (!validation) {
						throw new AuthenticationCaptchaIncorrectException(messages.getMessage(AuthResponseCode.SC_AUTHC_CAPTCHA_INCORRECT.getMsgKey(), 
								"Captcha was incorrect."));
					}
					
				}
		 		
		 		String username = obtainUsername(request);
				String password = obtainPassword(request);

				if (username == null) {
					username = "";
				}

				if (password == null) {
					password = "";
				}

				username = username.trim();

				authRequest = this.authenticationToken( username, password);
		 		
			}

			// Allow subclasses to set the "details" property
			setDetails(request, authRequest);

			return this.getAuthenticationManager().authenticate(authRequest);

		} catch (JsonParseException e) {
			throw new InternalAuthenticationServiceException(e.getMessage());
		} catch (JsonMappingException e) {
			throw new InternalAuthenticationServiceException(e.getMessage());
		} catch (IOException e) {
			throw new InternalAuthenticationServiceException(e.getMessage());
		}

	}

	protected AbstractAuthenticationToken authenticationToken(String username, String password) {
		return new UsernamePasswordAuthenticationToken( username, password);
	}
	
	/**
	 * Enables subclasses to override the composition of the captcha, such as by
	 * including additional values and a separator.
	 *
	 * @param request so that request attributes can be retrieved
	 *
	 * @return the captcha that will be presented in the <code>Authentication</code>
	 * request token to the <code>AuthenticationManager</code>
	 */
	protected String obtainCaptcha(HttpServletRequest request) {
		return request.getParameter(captchaParameter);
	}
	
	
	/**
	 * Enables subclasses to override the composition of the password, such as by
	 * including additional values and a separator.
	 * <p>
	 * This might be used for example if a postcode/zipcode was required in addition to
	 * the password. A delimiter such as a pipe (|) should be used to separate the
	 * password and extended value(s). The <code>AuthenticationDao</code> will need to
	 * generate the expected password in a corresponding manner.
	 * </p>
	 *
	 * @param request so that request attributes can be retrieved
	 *
	 * @return the password that will be presented in the <code>Authentication</code>
	 * request token to the <code>AuthenticationManager</code>
	 */
	protected String obtainPassword(HttpServletRequest request) {
		return request.getParameter(passwordParameter);
	}

	/**
	 * Enables subclasses to override the composition of the username, such as by
	 * including additional values and a separator.
	 *
	 * @param request so that request attributes can be retrieved
	 *
	 * @return the username that will be presented in the <code>Authentication</code>
	 * request token to the <code>AuthenticationManager</code>
	 */
	protected String obtainUsername(HttpServletRequest request) {
		return request.getParameter(usernameParameter);
	}

	/**
	 * Provided so that subclasses may configure what is put into the authentication
	 * request's details property.
	 *
	 * @param request that an authentication request is being created for
	 * @param authRequest the authentication request object that should have its details
	 * set
	 */
	protected void setDetails(HttpServletRequest request,
			AbstractAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}

	/**
	 * Sets the parameter name which will be used to obtain the username from the login
	 * request.
	 *
	 * @param usernameParameter the parameter name. Defaults to "username".
	 */
	public void setUsernameParameter(String usernameParameter) {
		Assert.hasText(usernameParameter, "Username parameter must not be empty or null");
		this.usernameParameter = usernameParameter;
	}

	/**
	 * Sets the parameter name which will be used to obtain the password from the login
	 * request..
	 *
	 * @param passwordParameter the parameter name. Defaults to "password".
	 */
	public void setPasswordParameter(String passwordParameter) {
		Assert.hasText(passwordParameter, "Password parameter must not be empty or null");
		this.passwordParameter = passwordParameter;
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

	public final String getUsernameParameter() {
		return usernameParameter;
	}

	public final String getPasswordParameter() {
		return passwordParameter;
	}
	

	protected boolean isOverRetryRemind(ServletRequest request, ServletResponse response) {
		if (null != getFailureCounter() && getFailureCounter().get(request, response, getRetryTimesKeyAttribute()) == getRetryTimesWhenAccessDenied()) {
			return true;
		}
		return false;
	}
	
	protected boolean isOverRetryTimes(ServletRequest request, ServletResponse response) {
		if (null != getFailureCounter() && getFailureCounter().get(request, response, getRetryTimesKeyAttribute()) >= getRetryTimesWhenAccessDenied()) {
			return true;
		}
		return false;
	}
	
	
	public boolean isPostOnly() {
		return postOnly;
	}
	
	public boolean isCaptchaRequired() {
		return captchaRequired;
	}

	public void setCaptchaRequired(boolean captchaRequired) {
		this.captchaRequired = captchaRequired;
	}

	public CaptchaResolver getCaptchaResolver() {
		return captchaResolver;
	}

	public void setCaptchaResolver(CaptchaResolver captchaResolver) {
		this.captchaResolver = captchaResolver;
	}

	public String getCaptchaParameter() {
		return captchaParameter;
	}

	public void setCaptchaParameter(String captchaParameter) {
		this.captchaParameter = captchaParameter;
	}

	public AuthenticatingFailureCounter getFailureCounter() {
		return failureCounter;
	}

	public void setFailureCounter(AuthenticatingFailureCounter failureCounter) {
		this.failureCounter = failureCounter;
	}
	
	public String getRetryTimesKeyAttribute() {
		return retryTimesKeyAttribute;
	}

	public void setRetryTimesKeyAttribute(String retryTimesKeyAttribute) {
		this.retryTimesKeyAttribute = retryTimesKeyAttribute;
	}

	public int getRetryTimesWhenAccessDenied() {
		return retryTimesWhenAccessDenied;
	}

	public void setRetryTimesWhenAccessDenied(int retryTimesWhenAccessDenied) {
		this.retryTimesWhenAccessDenied = retryTimesWhenAccessDenied;
	}

	public ObjectMapper getObjectMapper() {
		return objectMapper;
	}
	
}
