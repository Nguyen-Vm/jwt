package com.ruochuchina.jwt.controller;

import com.google.common.collect.Maps;
import com.ruochuchina.jwt.authority.AuthorityContext;
import com.ruochuchina.jwt.authority.AuthoritySession;
import com.ruochuchina.jwt.common.JwtAuthentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * @author RWM
 * @date 2018/9/20
 */
@RestController
@RequestMapping("/jwt")
public class JwtController {

    @Autowired
    private JwtAuthentication jwtAuthentication;

    @GetMapping("/login")
    public Map<String, String> login() {
        Map<String, String> map = Maps.newHashMap();
        map.put("pubKey", jwtAuthentication.calPubKey("111", "222"));
        map.put("signature", jwtAuthentication.calSignature("111", "222", 5 * 60 * 1000));
        return map;

    }

    @PostMapping("/go")
    public String go(@RequestParam String pubKey, @RequestParam String signature, AuthoritySession session) {
        return session.toString();
    }
}
