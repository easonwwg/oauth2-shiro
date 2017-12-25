/*
 * Copyright (c) 2013 Andaily Information Technology Co. Ltd
 * www.andaily.com
 * All rights reserved.
 *
 * This software is the confidential and proprietary information of
 * Andaily Information Technology Co. Ltd ("Confidential Information").
 * You shall not disclose such Confidential Information and shall use
 * it only in accordance with the terms of the license agreement you
 * entered into with Andaily Information Technology Co. Ltd.
 */
package com.monkeyk.os.oauth.token;

import com.monkeyk.os.web.WebUtils;
import com.monkeyk.os.oauth.OAuthHandler;
import com.monkeyk.os.oauth.OAuthTokenxRequest;
import com.monkeyk.os.oauth.validator.AbstractClientDetailsValidator;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletResponse;

/**
 * 2015/7/3
 * 抽象的类 封装oauth2Token处理的类
 * @author Shengzhao Li
 */
public abstract class AbstractOAuthTokenHandler extends OAuthHandler implements OAuthTokenHandler {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractOAuthTokenHandler.class);


    protected OAuthTokenxRequest tokenRequest;
    protected HttpServletResponse response;

    @Override
    public final void handle(OAuthTokenxRequest tokenRequest, HttpServletResponse response) throws OAuthProblemException, OAuthSystemException {
        this.tokenRequest = tokenRequest;
        this.response = response;

        //validate
        if (validateFailed()) {
            return;
        }
        handleAfterValidation();
    }


    /**
     * 通用方法 是否验证失败
     * @return
     * @throws OAuthSystemException
     */
    protected boolean validateFailed() throws OAuthSystemException {
        AbstractClientDetailsValidator validator = getValidator();
        LOG.debug("Use [{}] validate client: {}", validator, tokenRequest.getClientId());
        final OAuthResponse oAuthResponse = validator.validate();
        return checkAndResponseValidateFailed(oAuthResponse);
    }

    /**
     *如果验证失败，oAuthResponse返回不为null，返回异常页面
     * @param oAuthResponse
     * @return
     */
    protected boolean checkAndResponseValidateFailed(OAuthResponse oAuthResponse) {
        if (oAuthResponse != null) {
            LOG.debug("Validate OAuthAuthzRequest(client_id={}) failed", tokenRequest.getClientId());
            WebUtils.writeOAuthJsonResponse(response, oAuthResponse);
            return true;
        }
        return false;
    }

    /**
     * 待子类实现的方法 获取各种验证器
     * @return
     */
    protected abstract AbstractClientDetailsValidator getValidator();

    /**
     * 通用方法 获取clientID
     * @return
     */
    protected String clientId() {
        return tokenRequest.getClientId();
    }

    /**
     * 封装处理器验证之后的操作
     * @throws OAuthProblemException
     * @throws OAuthSystemException
     */
    protected abstract void handleAfterValidation() throws OAuthProblemException, OAuthSystemException;


}
