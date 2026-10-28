package org.springframework.security.boot.biz;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

import java.util.Objects;

public class CustomWebSecurityExpressionRoot  extends WebSecurityExpressionRoot {

    // private FilterInvocation filterInvocation;
    /** Allows direct access to the request object */
    public final HttpServletRequest request;

    public CustomWebSecurityExpressionRoot(Authentication a, FilterInvocation fi) {
        super(a, fi);
        this.request = fi.getRequest();
    }

    public CustomWebSecurityExpressionRoot(Authentication authentication, RequestAuthorizationContext context) {
        super(() -> authentication, context.getRequest());
        this.request = context.getRequest();
    }

    /**
     * Takes a specific IP address or a range using the IP/Netmask (e.g. 192.168.1.0/24 or
     * 202.24.0.0/14).
     *
     * @param ipAddress the address or range of addresses from which the request must
     * come.
     * @return true if the IP address of the current request is in the required range.
     */
    @Override
    public boolean hasIpAddress(String ipAddress) {
        String remoteAddr = Objects.toString(request.getRemoteAddr(), "");
        return (new IpAddressMatcher(ipAddress).matches(remoteAddr));
    }

}
