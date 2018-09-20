package com.ruochuchina.jwt.authority;

import javax.servlet.http.HttpServletRequest;

/**
 * @author RWM
 * @date 2018/5/10
 */
public class AuthoritySession {

    public String userId;

    public String roleId;

    public String domain;

    public String uri;

    public static AuthoritySession create(HttpServletRequest request) {
        AuthoritySession session = new AuthoritySession();
        session.domain = request.getServerName();
        session.uri = request.getRequestURI();
        return session;
    }

    @Override
    public String toString() {
        return "AuthoritySession{" +
                "userId='" + userId + '\'' +
                ", roleId='" + roleId + '\'' +
                ", domain='" + domain + '\'' +
                ", uri='" + uri + '\'' +
                '}';
    }
}
