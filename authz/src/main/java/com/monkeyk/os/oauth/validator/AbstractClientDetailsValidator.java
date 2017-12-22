package com.monkeyk.os.oauth.validator;

import com.monkeyk.os.domain.oauth.ClientDetails;
import com.monkeyk.os.domain.shared.BeanProvider;
import com.monkeyk.os.service.OauthService;
import org.apache.oltu.oauth2.as.request.OAuthRequest;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletResponse;
import java.util.Set;

/**
 * 15-6-13
 * <p>
 * 对各类 grant_type 的请求进行验证的公共类
 * 对不同的grant_type的请求进行验证抽象类
 * 将通用的行为(方法) 位于此
 *
 * @author Shengzhao Li
 */
public abstract class AbstractClientDetailsValidator {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractClientDetailsValidator.class);

    /**
     * oauth2服务接口
     */
    protected OauthService oauthService = BeanProvider.getBean(OauthService.class);

    /**
     * 封装的oauth2Request请求对象
     */
    protected OAuthRequest oauthRequest;

    /**
     * 封装的oauth2客户端对象
     */
    private ClientDetails clientDetails;

    /**
     * 构造函数
     *
     * @param oauthRequest
     */
    protected AbstractClientDetailsValidator(OAuthRequest oauthRequest) {
        this.oauthRequest = oauthRequest;
    }


    /**
     * 获取授权app的信息
     *
     * @return
     */
    protected ClientDetails clientDetails() {
        if (clientDetails == null) {
            clientDetails = oauthService.loadClientDetails(oauthRequest.getClientId());
        }
        return clientDetails;
    }


    /**
     * 无效的app
     * @return
     * @throws OAuthSystemException
     */
    protected OAuthResponse invalidClientErrorResponse() throws OAuthSystemException {
        return OAuthResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                .setError(OAuthError.TokenResponse.INVALID_CLIENT)
                .setErrorDescription("Invalid client_id '" + oauthRequest.getClientId() + "'")
                .buildJSONMessage();
    }

    /**
     * 无效的RedirectUrl
     * @return
     * @throws OAuthSystemException
     */
    protected OAuthResponse invalidRedirectUriResponse() throws OAuthSystemException {
        return OAuthResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                .setError(OAuthError.CodeResponse.INVALID_REQUEST)
                .setErrorDescription("Invalid redirect_uri '" + oauthRequest.getRedirectURI() + "'")
                .buildJSONMessage();
    }

    /**
     * 无效的授权范围（scope）
     * @return
     * @throws OAuthSystemException
     */
    protected OAuthResponse invalidScopeResponse() throws OAuthSystemException {
        return OAuthResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                .setError(OAuthError.CodeResponse.INVALID_SCOPE)
                .setErrorDescription("Invalid scope '" + oauthRequest.getScopes() + "'")
                .buildJSONMessage();
    }


    /**
     * 无效的app secret
     * @return
     * @throws OAuthSystemException
     */
    protected OAuthResponse invalidClientSecretResponse() throws OAuthSystemException {
        return OAuthResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
                .setError(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT)
                .setErrorDescription("Invalid client_secret by client_id '" + oauthRequest.getClientId() + "'")
                .buildJSONMessage();
    }


    /**
     * 验证客户端
     * @return
     * @throws OAuthSystemException
     */
    public final OAuthResponse validate() throws OAuthSystemException {
        final ClientDetails details = clientDetails();
        if (details == null) {
            return invalidClientErrorResponse();
        }

        return validateSelf(details);
    }


    /**
     * 排除指定的scope
     * @param scopes
     * @param clientDetails
     * @return
     */
    protected boolean excludeScopes(Set<String> scopes, ClientDetails clientDetails) {
        //read write
        final String clientDetailsScope = clientDetails.scope();
        for (String scope : scopes) {
            if (!clientDetailsScope.contains(scope)) {
                LOG.debug("Invalid scope - ClientDetails scopes '{}' exclude '{}'", clientDetailsScope, scope);
                return true;
            }
        }
        return false;
    }

    /**
     * 抽象的方法 验证客户端请求的合法性
     * @param clientDetails
     * @return
     * @throws OAuthSystemException
     */
    protected abstract OAuthResponse validateSelf(ClientDetails clientDetails) throws OAuthSystemException;
}
