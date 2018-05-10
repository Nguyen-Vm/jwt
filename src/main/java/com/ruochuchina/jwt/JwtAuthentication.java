package com.ruochuchina.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.Verification;
import com.google.common.base.Joiner;
import org.nguyen.foun.utils.DateUtils;

public class JwtAuthentication {

    private final String secret;

    public static JwtAuthentication create(String secret) {
        return new JwtAuthentication(secret);
    }

    private final JWTCreator.Builder jwtBuilder;
    private final Verification verification;
    private final DesAlgorithm algorithm;
    private JwtAuthentication(String secret) {
        try {
            this.secret = secret;
            this.jwtBuilder = JWT.create()
                    .withAudience("ruochuchina.com")
                    .withClaim(PublicClaims.ISSUER, "http://ruochuchina.com");

            this.verification = JWT.require(Algorithm.HMAC256(secret))
                    .withAudience("ruochuchina.com")
                    .withClaim(PublicClaims.ISSUER, "http://ruochuchina.com")
                    .acceptLeeway(1L);

            this.algorithm = DesAlgorithm.create(secret);
        }catch (Exception e) {
            throw new RuntimeException("initial jwt authentication error......", e);
        }
    }

    private String joiner(Object ... objects) {
        return Joiner.on(":").join(objects);
    }

    public String calPubKey(String userId, String roleId) {
        long now = DateUtils.time();
        String msg = now % 2 == 0 ? joiner(userId, now, roleId) : joiner(roleId, now, userId);
        return algorithm.decrypt(msg);
    }

    public static void main(String[] args) {
        JwtAuthentication jwtAuthentication = new JwtAuthentication("ruochuchina");

    }
}
