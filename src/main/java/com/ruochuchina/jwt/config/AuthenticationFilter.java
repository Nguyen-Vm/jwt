package com.ruochuchina.jwt.config;

import com.ruochuchina.jwt.authority.AuthorityContext;
import com.ruochuchina.jwt.authority.AuthoritySession;
import com.ruochuchina.jwt.authority.IAuthenticationFilter;
import com.ruochuchina.jwt.common.JwtAuthentication;
import org.springframework.context.ApplicationContext;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author RWM
 * @date 2018/9/20
 */
public class AuthenticationFilter implements IAuthenticationFilter {

    private final ApplicationContext context;

    AuthenticationFilter(ApplicationContext context) {
        this.context = context;
    }

    @Override
    public void authentication(AuthoritySession session,
                               HttpServletRequest request,
                               HttpServletResponse response,
                               FilterChain chain) throws Exception {
        if ("GET".equalsIgnoreCase(request.getMethod())) {
            AuthorityContext.get().setSession(session);
            chain.doFilter(request, response);
            return;
        }
        AuthoritySession authoritySession = verifyKeySignature(request);
        if (authoritySession != null) {
            session.userId = authoritySession.userId;
            session.roleId = authoritySession.roleId;
            AuthorityContext.get().setSession(session);
            chain.doFilter(request, response);
        }
    }

    private AuthoritySession verifyKeySignature(HttpServletRequest request) {
        String pubKey = request.getParameter("pubKey");
        String signature = request.getParameter("signature");
        return context.getBean(JwtAuthentication.class).verifySignature(pubKey, signature);
    }
}
