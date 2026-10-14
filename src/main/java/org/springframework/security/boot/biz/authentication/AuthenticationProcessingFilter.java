package org.springframework.security.boot.biz.authentication;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.IOException;
import java.util.Objects;

/**
 * Base authentication processing filter for the security-biz starter.
 * <p>
 * Extends Spring Security's {@link AbstractAuthenticationProcessingFilter}
 * with common HTTP header handling (uid / sign / location / app metadata)
 * used by the feature-specific authentication filters in downstream starters.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public abstract class AuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

	/** Default value used when the longitude/latitude headers are absent. */
	public static final String DEFAULT_LONGITUDE_LATITUDE = "0.000000";

	/**
	 * HTTP Authorization header, equal to <code>X-Uid</code>
	 */
	public static final String UID_HEADER = "X-Uid";
	/**
	 * HTTP Authorization header, equal to <code>X-Sign</code>
	 */
	public static final String SIGN_HEADER = "X-Sign";
	/**
	 * HTTP Authorization header, equal to <code>X-Longitude</code>
	 */
	public static final String LONGITUDE_HEADER = "X-Longitude";
	/**
	 * HTTP Authorization header, equal to <code>X-Latitude</code>
	 */
	public static final String LATITUDE_HEADER = "X-Latitude";
	/**
	 * HTTP Authorization header, equal to <code>X-APP-ID</code>
	 */
	public static final String APP_ID_HEADER = "X-APP-ID";
	/**
	 * HTTP Authorization header, equal to <code>X-APP-CHANNEL</code>
	 */
	public static final String APP_CHANNEL_HEADER = "X-APP-CHANNEL";
	/**
	 * HTTP Authorization header, equal to <code>X-APP-VERSION</code>
	 */
	public static final String APP_VERSION_HEADER = "X-APP-VERSION";

	/** Configurable name of the user-id header (default {@value #UID_HEADER}). */
	private String uidHeaderName = UID_HEADER;
	/** Configurable name of the signature header (default {@value #SIGN_HEADER}). */
	private String signHeaderName = SIGN_HEADER;
	/** Configurable name of the longitude header (default {@value #LONGITUDE_HEADER}). */
	private String longitudeHeaderName = LONGITUDE_HEADER;
	/** Configurable name of the latitude header (default {@value #LATITUDE_HEADER}). */
	private String latitudeHeaderName = LATITUDE_HEADER;
	/** Configurable name of the app-id header (default {@value #APP_ID_HEADER}). */
	private String appIdHeaderName = APP_ID_HEADER;
	/** Configurable name of the app-channel header (default {@value #APP_CHANNEL_HEADER}). */
	private String appChannelHeaderName = APP_CHANNEL_HEADER;
	/** Configurable name of the app-version header (default {@value #APP_VERSION_HEADER}). */
	private String appVersionHeaderName = APP_VERSION_HEADER;
	private final String format = "{} ：{}";
	
	// ~ Static fields/initializers
	// =====================================================================================
	
	protected static Logger logger = LoggerFactory.getLogger(AuthenticationProcessingFilter.class);
	
	// ~ Constructors
	// ===================================================================================================
	
	/**
	 * @param defaultFilterProcessesUrl the default value for &lt;tt&gt;filterProcessesUrl&lt;/tt&gt;.
	 */
	protected AuthenticationProcessingFilter(String defaultFilterProcessesUrl) {
		super(defaultFilterProcessesUrl);
	}

	/**
	 * Creates a new instance
	 *
	 * @param requiresAuthenticationRequestMatcher the {@link RequestMatcher} used to
	 * determine if authentication is required. Cannot be null.
	 */
	protected AuthenticationProcessingFilter(
			RequestMatcher requiresAuthenticationRequestMatcher) {
		super(requiresAuthenticationRequestMatcher);
	}

	// ~ Methods
	// ========================================================================================================

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		
		if(Objects.isNull(RequestContextHolder.getRequestAttributes())) {
			// Set RequestContextHolder
			ServletRequestAttributes requestAttributes = new ServletRequestAttributes(request, response);
			RequestContextHolder.setRequestAttributes(requestAttributes, true);
		}
		
		// real method
		return this.doAttemptAuthentication(request, response);

	}
	

	/**
	 * Performs actual authentication.
	 * <p>
	 * The implementation should do one of the following:
	 * <ol>
	 * <li>Return a populated authentication token for the authenticated user, indicating
	 * successful authentication</li>
	 * <li>Return null, indicating that the authentication process is still in progress.
	 * Before returning, the implementation should perform any additional work required to
	 * complete the process.</li>
	 * <li>Throw an &lt;tt&gt;AuthenticationException&lt;/tt&gt; if the authentication process fails</li>
	 * </ol>
	 *
	 * @param request from which to extract parameters and perform the authentication
	 * @param response the response, which may be needed if the implementation has to do a
	 * redirect as part of a multi-stage authentication process (such as OpenID).
	 *
	 * @return the authenticated user token, or null if authentication is incomplete.
	 *
	 * @throws AuthenticationException if authentication fails.
	 */
	public abstract Authentication doAttemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException, IOException,
			ServletException;

	protected void setDetails(HttpServletRequest request, AbstractAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}
	
	protected double obtainLongitude(HttpServletRequest request) {
		return Double.parseDouble(StringUtils.defaultIfBlank(request.getHeader(getLongitudeHeaderName()), DEFAULT_LONGITUDE_LATITUDE));
	}
	
	protected double obtainLatitude(HttpServletRequest request) {
		return Double.parseDouble(StringUtils.defaultIfBlank(request.getHeader(getLatitudeHeaderName()), DEFAULT_LONGITUDE_LATITUDE));
	}
	
	protected String obtainUid(HttpServletRequest request) {
		String uid = request.getHeader(getUidHeaderName());
		logger.debug(format, getUidHeaderName(), uid);
		return uid;
	}
	
	protected String obtainSign(HttpServletRequest request) {
		String sign = request.getHeader(getSignHeaderName());
		logger.debug(format, getSignHeaderName(), sign);
		return sign;
	}
	
	protected String obtainAppId(HttpServletRequest request) {
		String appId = request.getHeader(getAppIdHeaderName());
		logger.debug(format,  getAppIdHeaderName(), appId);
		return appId;
	}
	
	protected String obtainAppChannel(HttpServletRequest request) {
		String appChannel = request.getHeader(getAppChannelHeaderName());
		logger.debug(format,  getAppChannelHeaderName(), appChannel);
		return appChannel;
	}
	
	protected String obtainAppVersion(HttpServletRequest request) {
		String appVersion = request.getHeader(getAppVersionHeaderName());
		logger.debug(format,  getAppVersionHeaderName(), appVersion);
		return appVersion;
	}
	
	public String getUidHeaderName() {
		return uidHeaderName;
	}

	public void setUidHeaderName(String uidHeaderName) {
		this.uidHeaderName = uidHeaderName;
	}
	
	public String getSignHeaderName() {
		return signHeaderName;
	}

	public void setSignHeaderName(String signHeaderName) {
		this.signHeaderName = signHeaderName;
	}

	public String getLongitudeHeaderName() {
		return longitudeHeaderName;
	}

	public void setLongitudeHeaderName(String longitudeHeaderName) {
		this.longitudeHeaderName = longitudeHeaderName;
	}

	public String getLatitudeHeaderName() {
		return latitudeHeaderName;
	}

	public void setLatitudeHeaderName(String latitudeHeaderName) {
		this.latitudeHeaderName = latitudeHeaderName;
	}

	public String getAppIdHeaderName() {
		return appIdHeaderName;
	}

	public void setAppIdHeaderName(String appIdHeaderName) {
		this.appIdHeaderName = appIdHeaderName;
	}

	public String getAppChannelHeaderName() {
		return appChannelHeaderName;
	}

	public void setAppChannelHeaderName(String appChannelHeaderName) {
		this.appChannelHeaderName = appChannelHeaderName;
	}

	public String getAppVersionHeaderName() {
		return appVersionHeaderName;
	}

	public void setAppVersionHeaderName(String appVersionHeaderName) {
		this.appVersionHeaderName = appVersionHeaderName;
	}
	
}
