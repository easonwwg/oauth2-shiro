package com.monkeyk.os.oauth.shiro;

import org.apache.shiro.authc.RememberMeAuthenticationToken;

/**
 * 2015/9/29
 * 实现 AuthenticationToken （RememberMeAuthenticationToken继承RememberMeAuthenticationToken）
 *
 * @author Shengzhao Li
 */
public class OAuth2Token implements RememberMeAuthenticationToken {

    private static final long serialVersionUID = 8587854556973099598L;

    private String accessToken;

    private String userId;

    private boolean rememberMe = false;

    private String resourceId;

    public OAuth2Token(String accessToken, String resourceId) {
        this.accessToken = accessToken;
        this.resourceId = resourceId;
    }

    public String getResourceId() {
        return resourceId;
    }

    @Override
    public boolean isRememberMe() {
        return rememberMe;
    }

    public OAuth2Token setUserId(String userId) {
        this.userId = userId;
        return this;
    }

    public OAuth2Token setRememberMe(boolean rememberMe) {
        this.rememberMe = rememberMe;
        return this;
    }

    @Override
    public Object getPrincipal() {
        return userId;
    }

    @Override
    public Object getCredentials() {
        return accessToken;
    }
}
