package com.cos.security1.controller;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@Slf4j
@RequiredArgsConstructor
public class IndexController {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/testV1/login")
    public @ResponseBody String loginTestV1(Authentication authentication){
        System.out.println("=====================");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("principalDetails.getUser() = " + principalDetails.getUser());
        return "세션 정보 확인하기";
    }
    @GetMapping("/testV2/login")
    public @ResponseBody String loginTestV2(@AuthenticationPrincipal PrincipalDetails userDetails){
        System.out.println("=====================");
        System.out.println("userDetails.getUsername() = " + userDetails.getUser());
        return "세션 정보 확인하기";
    }
    @GetMapping("/test/oauth/login/v1")
    public @ResponseBody String loginTestOauthV1(Authentication authentication){
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("oAuth2User.getAttributes() = " + oAuth2User.getAttributes());
        return "세션 정보 확인하기";
    }
    @GetMapping("/test/oauth/login/v2")
    public @ResponseBody String loginTestOauthV2(@AuthenticationPrincipal OAuth2User oAuth2User){
        System.out.println("oAuth2User.getAttributes() = " + oAuth2User.getAttributes());
        return "세션 정보 확인하기";
    }
    @GetMapping({ "", "/" })
    @ResponseBody
    public String index() {
        return "index";
    }
    @GetMapping("/user")
    @ResponseBody
    public String user(@AuthenticationPrincipal PrincipalDetails principalDetails){
        System.out.println("principalDetails.getUser() = " + principalDetails.getUser());
        return "user";
    }
    @GetMapping("/admin")
    @ResponseBody
    public String admin(){
        return "admin";
    }
    @GetMapping("/manager")
    @ResponseBody
    public String manager(){
        return "manager";
    }
    @GetMapping("/login")
    public String loginForm(){
        return "loginForm";
    }
    @GetMapping("/join")
    public String joinForm(){
        return "joinForm";
    }
    @PostMapping("/join")
    public String join(User user){
        log.info(String.valueOf(user));
        user.setRole("ROLE_USER");
        String rawPassword=user.getPassword();
        String encPassword=bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user);
        return "redirect:/login";
    }
    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info(){
        return "개인 정보";
    }
    @PreAuthorize("hasRole('ROLE_MANAGER')or hasRole('ROLE_USER')")
    @GetMapping("/data")
    public @ResponseBody String data(){
        return "개인 정보";
    }


}
