package org.springframework.security.boot.biz;

import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.expression.DefaultHttpSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

public class CustomWebSecurityExpressionHandler extends DefaultHttpSecurityExpressionHandler {

    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    private String defaultRolePrefix = "ROLE_";

    @Override
    protected SecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication,
                                                                         RequestAuthorizationContext context) {
        WebSecurityExpressionRoot root = new CustomWebSecurityExpressionRoot(authentication, context);
        root.setPermissionEvaluator(getPermissionEvaluator());
        root.setTrustResolver(this.trustResolver);
        root.setRoleHierarchy(this.getRoleHierarchy());
        root.setDefaultRolePrefix(this.defaultRolePrefix);
        return root;
    }

    @Override
    public void setTrustResolver(AuthenticationTrustResolver trustResolver){
        super.setTrustResolver(trustResolver);
        this.trustResolver = trustResolver;
    }

    @Override
    public void setDefaultRolePrefix(String defaultRolePrefix) {
        super.setDefaultRolePrefix(defaultRolePrefix);
        this.defaultRolePrefix = defaultRolePrefix;
    }

}
