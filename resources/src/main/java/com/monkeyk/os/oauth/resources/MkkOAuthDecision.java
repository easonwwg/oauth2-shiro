package com.monkeyk.os.oauth.resources;

import com.monkeyk.os.domain.rs.RSOAuthClient;
import org.apache.oltu.oauth2.rsfilter.OAuthClient;
import org.apache.oltu.oauth2.rsfilter.OAuthDecision;

import java.security.Principal;

/**
 * 2015/7/8
 * 实现oauth2接口OAuthDecision
 * @author Shengzhao Li
 */
public class MkkOAuthDecision implements OAuthDecision {


    private boolean authorized;

    /**
     * 凭证
     */
    private Principal principal;

    /**
     * 客户端对象
     */
    private RSOAuthClient oAuthClient;

    public MkkOAuthDecision() {
    }

    public boolean isAuthorized() {
        return authorized;
    }

    @Override
    public Principal getPrincipal() {
        return principal;
    }

    @Override
    public OAuthClient getOAuthClient() {
        return oAuthClient;
    }

    public MkkOAuthDecision setPrincipal(Principal principal) {
        this.principal = principal;
        return this;
    }

    public MkkOAuthDecision setOAuthClient(RSOAuthClient oAuthClient) {
        this.oAuthClient = oAuthClient;
        return this;
    }

    public MkkOAuthDecision setAuthorized(boolean authorized) {
        this.authorized = authorized;
        return this;
    }

    @Override
    public String toString() {
        return "{" +
                "authorized=" + authorized +
                ", principal=" + principal +
                ", oAuthClient=" + oAuthClient +
                '}';
    }
}
