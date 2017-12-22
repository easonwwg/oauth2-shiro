package com.monkeyk.os.oauth.authorize;

import com.monkeyk.os.oauth.OAuthAuthxRequest;
import com.monkeyk.os.oauth.OAuthHandler;
import com.monkeyk.os.oauth.validator.AbstractClientDetailsValidator;
import com.monkeyk.os.web.WebUtils;
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


    /**
     * 封装的oauth2Request对象
     */
    protected OAuthAuthxRequest oauthRequest;

    /**
     * httpRequest对象
     */
    protected HttpServletResponse response;

    protected boolean userFirstLogged = false;
    protected boolean userFirstApproved = false;


    public AbstractAuthorizeHandler(OAuthAuthxRequest oauthRequest, HttpServletResponse response) {
        this.oauthRequest = oauthRequest;
        this.response = response;
    }

    /**
     * 客户端请求验证器
     *
     * @return
     */
    protected abstract AbstractClientDetailsValidator getValidator();

    /**
     * 抽象的自定义返回内容
     *
     * @throws OAuthSystemException
     * @throws IOException
     */
    protected abstract void handleResponse() throws OAuthSystemException, IOException;

    //region validateFailed()验证请求的合法

    /**
     * 返回respponse验证
     *
     * @param oAuthResponse
     * @return
     */
    protected boolean checkAndResponseValidateFailed(OAuthResponse oAuthResponse) {
        if (oAuthResponse != null) {
            LOG.debug("Validate OAuthAuthzRequest(client_id={}) failed", oauthRequest.getClientId());
            WebUtils.writeOAuthJsonResponse(response, oAuthResponse);
            return true;
        }
        return false;
    }

    /**
     * 获取请求的clientId
     *
     * @return
     */
    protected String clientId() {
        return oauthRequest.getClientId();
    }

    /**
     * 验证请求是否合法，主要是针对参数做基本的校验，
     * 重定向链接，客户端ID授权范围等这些信息与注册的是否相同
     *
     * @return
     * @throws OAuthSystemException
     */
    protected boolean validateFailed() throws OAuthSystemException {
        //客户端验证
        AbstractClientDetailsValidator validator = getValidator();
        LOG.debug("Use [{}] validate client: {}", validator, oauthRequest.getClientId());
        final OAuthResponse oAuthResponse = validator.validate();
        return checkAndResponseValidateFailed(oAuthResponse);
    }
    //endregion

    //region goApproval() 用户授权的认证

    /**
     * 如果授权了 返回false放行
     * 如果未授权，返回true，并且跳转找授权页面
     *
     * @return
     * @throws ServletException
     * @throws IOException
     */
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
    //endregion

    //region submitApproval() 用户同意授权与否的验证

    /**
     * 登录类似，也是提交用户批准或拒绝了权限请求
     * true is submit failed, otherwise return false
     *
     * @return
     * @throws IOException
     * @throws OAuthSystemException
     */
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

    /**
     * 用户拒绝授权的回掉
     *
     * @throws IOException
     * @throws OAuthSystemException
     */
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
    //endregion

    //region goLogin()判断用户是否登录过

    /**
     * 用户是否认证
     *
     * @return
     */
    protected boolean isUserAuthenticated() {
        final Subject subject = SecurityUtils.getSubject();
        return subject.isAuthenticated();
    }

    /**
     * 用户是否需要登陆的验证
     *
     * @return
     */
    protected boolean isNeedUserLogin() {
        return !isUserAuthenticated() && !isPost();
    }


    /**
     * 是否需要登陆的验证
     *
     * @return
     * @throws ServletException
     * @throws IOException
     */
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
    //endregion

    //region submitLogin() 这个请求如果是从登录页面提交过来的那么就提交用户的登录，这个框架中交给shiro去做登录相关的操作

    /**
     * true，让用户登陆，false表示登陆成功直接下一步处理
     *
     * @return
     */
    private boolean isSubmitLogin() {
        return !isUserAuthenticated() && isPost();
    }

    /**
     * @return 返回false是登陆成功，true为登陆失败
     * @throws ServletException
     * @throws IOException
     */
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

    /**
     * 创建UserNamePasswordToken对象，根据用户穿入的username和password
     *
     * @return
     */
    private UsernamePasswordToken createUsernamePasswordToken() {
        final HttpServletRequest request = oauthRequest.request();
        final String username = request.getParameter(REQUEST_USERNAME);
        final String password = request.getParameter(REQUEST_PASSWORD);
        return new UsernamePasswordToken(username, password);
    }

    /**
     * 是否为post请求的封装
     *
     * @return
     */
    protected boolean isPost() {
        return RequestMethod.POST.name().equalsIgnoreCase(oauthRequest.request().getMethod());
    }
    //endregion


    /**
     * 验证处理的请求
     *
     * @throws OAuthSystemException
     * @throws ServletException
     * @throws IOException
     */
    public void handle() throws OAuthSystemException, ServletException, IOException {
        //验证请求是否合法，主要是针对参数做基本的校验，重定向链接，客户端ID授权范围等这些信息与注册的是否相同。
        if (validateFailed()) {
            return;
        }

        //判断用户是否登录过，shiro会进行判断根据session判断。因此多个应用使用同一个授权服务的话，是可以直接跳过登录步骤的也就实现了单点登录的效果。
        //如果没有登录的话，这一步的请求会被重定向至登录页面。（登录也得隐藏域会带上这些参数）
        if (goLogin()) {
            return;
        }

        //这个请求如果是从登录页面提交过来的，那么就提交用户的登录，这个框架中交给shiro去做登录相关的操作。
        if (submitLogin()) {
            return;
        }

        // 本系统中把登录和授权放在两个步骤中完成，有点像新浪微博的方式，
        // QQ是一步完成授权。用户未授权则跳转授权页面
        if (goApproval()) {
            return;
        }

        //与登录类似，也是提交用户批准或拒绝了权限请求
        if (submitApproval()) {
            return;
        }

        //以上任意一步没有通过都是授权失败会进行相应处理，如果都通过了就发放Code码
        handleResponse();
    }

}
