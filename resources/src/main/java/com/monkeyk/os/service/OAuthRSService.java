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
package com.monkeyk.os.service;

import com.monkeyk.os.domain.oauth.AccessToken;
import com.monkeyk.os.domain.oauth.ClientDetails;

/**
 * 2015/7/8
 *
 * @author Shengzhao Li
 */

public interface OAuthRSService {

    /**
     * 根据tokenid获取token的详细信息
     * @param tokenId
     * @return
     */
    AccessToken loadAccessTokenByTokenId(String tokenId);

    /**
     * 根据客户端id和resourceIds获取客户端的详细信息
     * @param clientId
     * @param resourceIds
     * @return
     */
    ClientDetails loadClientDetails(String clientId, String resourceIds);

}