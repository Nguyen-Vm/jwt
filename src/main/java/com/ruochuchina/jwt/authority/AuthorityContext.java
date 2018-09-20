package com.ruochuchina.jwt.authority;

/**
 * @author RWM
 * @date 2018/9/20
 */
public class AuthorityContext {

    private AuthoritySession session;
    private static ThreadLocal<AuthorityContext> holder = ThreadLocal.withInitial(AuthorityContext::new);

    public static AuthorityContext get() {
        return holder.get();
    }

    public AuthoritySession getSession() {
        return session;
    }

    public void setSession(AuthoritySession session) {
        this.session = session;
    }

    public void clear() {
        holder.remove();
    }
}
