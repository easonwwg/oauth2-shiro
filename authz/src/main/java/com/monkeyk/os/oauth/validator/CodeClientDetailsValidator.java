package com.monkeyk.os.oauth.validator;

import com.monkeyk.os.domain.oauth.ClientDetails;
import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletResponse;
import java.util.Set;

/**
 * 15-6-13
 * 授权码模式客户端验证
 *
 * @author Shengzhao Li
 */
public class CodeClientDetailsValidator extends AbstractClientDetailsValidator {

    private static final Logger LOG = LoggerFactory.getLogger(CodeClientDetailsValidator.class);

    /**
     * 构造器
     *
     * @param oauthRequest
     */
    public CodeClientDetailsValidator(OAuthAuthzRequest oauthRequest) {
        super(oauthRequest);
    }


    /**
     * 授权码模式验证
     * grant_type="authorization_code"
     * ?response_type=code&scope=read,write&client_id=[client_id]&redirect_uri=[redirect_uri]&state=[state]
     *
     * @param clientDetails
     * @return
     * @throws OAuthSystemException
     */
    @Override
    public OAuthResponse validateSelf(ClientDetails clientDetails) throws OAuthSystemException {
        //验证回掉url
        final String redirectURI = oauthRequest.getRedirectURI();
        if (redirectURI == null || !redirectURI.equals(clientDetails.getRedirectUri())) {
            LOG.debug("Invalid redirect_uri '{}' by response_type = 'code', client_id = '{}'", redirectURI, clientDetails.getClientId());
            return invalidRedirectUriResponse();
        }

        //验证scope授权范围 有一个授权不存在，就返回错误
        final Set<String> scopes = oauthRequest.getScopes();
        if (scopes.isEmpty() || excludeScopes(scopes, clientDetails)) {
            return invalidScopeResponse();
        }

        //验证url中的state 如果为空，就返回state的错误
        final String state = getState();
        if (StringUtils.isEmpty(state)) {
            LOG.debug("Invalid 'state', it is required, but it is empty");
            return invalidStateResponse();
        }
        return null;
    }

    /**
     * 获取url中的参数state
     *
     * @return
     */
    private String getState() {
        return ((OAuthAuthzRequest) oauthRequest).getState();
    }

    /**
     * 无效的state
     *
     * @return
     * @throws OAuthSystemException
     */
    private OAuthResponse invalidStateResponse() throws OAuthSystemException {
        return OAuthResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
                .setError(OAuthError.CodeResponse.INVALID_REQUEST)
                .setErrorDescription("Parameter 'state'  is required")
                .buildJSONMessage();
    }

}
