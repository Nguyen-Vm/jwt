package com.ruochuchina.jwt.config;

import com.ruochuchina.jwt.common.JwtAuthentication;
import com.ruochuchina.jwt.resolver.AuthorityArgumentResolver;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurationSupport;

import java.util.List;

/**
 * @author RWM
 * @date 2018/9/20
 */
@Configuration
public class ApplicationConfig extends WebMvcConfigurationSupport {

    @Override
    protected void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
        argumentResolvers.add(new AuthorityArgumentResolver());
    }

    @Bean
    public JwtAuthentication jwtAuthentication() {
        return JwtAuthentication.create("ruochuchina");
    }

    @Bean
    public AuthenticationFilter filter(ApplicationContext context) {
        return new AuthenticationFilter(context);
    }
}
