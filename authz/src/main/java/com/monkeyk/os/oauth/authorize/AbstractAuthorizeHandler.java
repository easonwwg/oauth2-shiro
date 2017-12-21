package com.monkeyk.os.oauth.authorize;

import com.monkeyk.os.web.WebUtils;
import com.monkeyk.os.oauth.OAuthAuthxRequest;
import com.monkeyk.os.oauth.OAuthHandler;
import com.monkeyk.os.oauth.validator.AbstractClientDetailsValidator;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.monkeyk.os.domain.oauth.Constants.*;

/**
 * 2015/6/25
 *
 * @author Shengzhao Li
 */
public abstract class AbstractAuthorizeHandler extends OAuthHandler {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractAuthorizeHandler.class);


    protected OAuthAuthxRequest oauthRequest;
    protected HttpServletResponse response;

    protected boolean userFirstLogged = false;
    protected boolean userFirstApproved = false;


    public AbstractAuthorizeHandler(OAuthAuthxRequest oauthRequest, HttpServletResponse response) {
        this.oauthRequest = oauthRequest;
        this.response = response;
    }


    protected boolean validateFailed() throws OAuthSystemException {
        AbstractClientDetailsValidator validator = getValidator();
        LOG.debug("Use [{}] validate client: {}", validator, oauthRequest.getClientId());

        final OAuthResponse oAuthResponse = validator.validate();
        return checkAndResponseValidateFailed(oAuthResponse);
    }

    protected abstract AbstractClientDetailsValidator getValidator();

    protected boolean checkAndResponseValidateFailed(OAuthResponse oAuthResponse) {
        if (oAuthResponse != null) {
            LOG.debug("Validate OAuthAuthzRequest(client_id={}) failed", oauthRequest.getClientId());
            WebUtils.writeOAuthJsonResponse(response, oAuthResponse);
            return true;
        }
        return false;
    }

    protected String clientId() {
        return oauthRequest.getClientId();
    }

    protected boolean isUserAuthenticated() {
        final Subject subject = SecurityUtils.getSubject();
        return subject.isAuthenticated();
    }

    protected boolean isNeedUserLogin() {
        return !isUserAuthenticated() && !isPost();
    }


    protected boolean goApproval() throws ServletException, IOException {
        if (userFirstLogged && !clientDetails().trusted()) {
            //go to approval
            LOG.debug("Go to oauth_approval, clientId: '{}'", clientDetails().getClientId());
            final HttpServletRequest request = oauthRequest.request();
            request.getRequestDispatcher(OAUTH_APPROVAL_VIEW)
                    .forward(request, response);
            return true;
        }
        return false;
    }

    //true is submit failed, otherwise return false
    protected boolean submitApproval() throws IOException, OAuthSystemException {
        if (isPost() && !clientDetails().trusted()) {
            //submit approval
            final HttpServletRequest request = oauthRequest.request();
            final String oauthApproval = request.getParameter(REQUEST_USER_OAUTH_APPROVAL);
            if (!"true".equalsIgnoreCase(oauthApproval)) {
                //Deny action
                LOG.debug("User '{}' deny access", SecurityUtils.getSubject().getPrincipal());
                responseApprovalDeny();
                return true;
            } else {
                userFirstApproved = true;
                return false;
            }
        }
        return false;
    }

    protected void responseApprovalDeny() throws IOException, OAuthSystemException {

        final OAuthResponse oAuthResponse = OAuthASResponse.errorResponse(HttpServletResponse.SC_FOUND)
                .setError(OAuthError.CodeResponse.ACCESS_DENIED)
                .setErrorDescription("User denied access")
                .location(clientDetails().getRedirectUri())
                .setState(oauthRequest.getState())
                .buildQueryMessage();
        LOG.debug("'ACCESS_DENIED' response: {}", oAuthResponse);

        WebUtils.writeOAuthQueryResponse(response, oAuthResponse);

        //user logout when deny
        final Subject subject = SecurityUtils.getSubject();
        subject.logout();
        LOG.debug("After 'ACCESS_DENIED' call logout. user: {}", subject.getPrincipal());
    }


    protected boolean goLogin() throws ServletException, IOException {
        if (isNeedUserLogin()) {
            //go to login
            LOG.debug("Forward to Oauth login by client_id '{}'", oauthRequest.getClientId());
            final HttpServletRequest request = oauthRequest.request();
            //跳转到授权登陆页面
            request.getRequestDispatcher(OAUTH_LOGIN_VIEW)
                    .forward(request, response);
            return true;
        }
        return false;
    }


    /**
     *
     * @return 返回false是登陆
     * @throws ServletException
     * @throws IOException
     */
    //true is login failed, false is successful
    protected boolean submitLogin() throws ServletException, IOException {
        if (isSubmitLogin()) {
            //login flow
            try {
                //验证form表单
                UsernamePasswordToken token = createUsernamePasswordToken();
                SecurityUtils.getSubject().login(token);

                LOG.debug("Submit login successful");
                this.userFirstLogged = true;
                return false;
            } catch (Exception ex) {
                //login failed
                LOG.debug("Login failed, back to login page too", ex);

                final HttpServletRequest request = oauthRequest.request();
                request.setAttribute("oauth_login_error", true);
                request.getRequestDispatcher(OAUTH_LOGIN_VIEW)
                        .forward(request, response);
                return true;
            }
        }
        return false;
    }

    private UsernamePasswordToken createUsernamePasswordToken() {
        final HttpServletRequest request = oauthRequest.request();
        final String username = request.getParameter(REQUEST_USERNAME);
        final String password = request.getParameter(REQUEST_PASSWORD);
        return new UsernamePasswordToken(username, password);
    }

    private boolean isSubmitLogin() {
        return !isUserAuthenticated() && isPost();
    }

    protected boolean isPost() {
        return RequestMethod.POST.name().equalsIgnoreCase(oauthRequest.request().getMethod());
    }

    public void handle() throws OAuthSystemException, ServletException, IOException {
        ////验证请求是否合法，主要是针对参数做基本的校验，重定向链接，客户端ID授权范围等这些信息与注册的是否相同。
        if (validateFailed()) {
            return;
        }

        ////判断用户是否登录过，shiro会进行判断根据session判断。因此多个应用使用同一个授权服务的话，是可以直接跳过登录步骤的也就实现了单点登录的效果。
        //如果没有登录的话，这一步的请求会被重定向至登录页面。（登录也得隐藏域会带上这些参数）
        if (goLogin()) {
            return;
        }

        ////这个请求如果是从登录页面提交过来的，那么就提交用户的登录，这个框架中交给shiro去做登录相关的操作。
        if (submitLogin()) {
            return;
        }

        // // 本系统中把登录和授权放在两个步骤中完成，有点像新浪微博的方式，
        // QQ是一步完成授权。用户未授权则跳转授权页面
        if (goApproval()) {
            return;
        }

        ////与登录类似，也是提交用户批准或拒绝了权限请求
        if (submitApproval()) {
            return;
        }

        ////以上任意一步没有通过都是授权失败会进行相应处理，如果都通过了就发放Code码
        handleResponse();
    }

    //Handle custom response content
    protected abstract void handleResponse() throws OAuthSystemException, IOException;
}
