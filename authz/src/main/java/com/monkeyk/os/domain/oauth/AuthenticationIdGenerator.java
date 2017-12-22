package com.monkeyk.os.domain.oauth;

/**
 * 15-6-20
 * 认证id生成器接口
 *
 * @author Shengzhao Li
 */

public interface AuthenticationIdGenerator {

    /**
     * @param clientId 客户端id
     * @param username 用户名
     * @param scope    授权的范围
     * @return
     */
    public String generate(String clientId, String username, String scope);

}