package com.cos.security1.config.auth;


import com.cos.security1.model.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;


@Getter
public class PrincipalDetails implements UserDetails, OAuth2User {
    private User user;
    private Map<String,Object>attributes;
    //일반 로그인
    public PrincipalDetails(User user) {
        this.user = user;
    }
    //Oauth로그인
    public PrincipalDetails(User user,Map<String,Object>attributes) {
        this.user = user;
        this.attributes=attributes;
    }


    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    //해당 user의 권한을 리턴하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority>collect=new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        //계정 만료 안됫지??
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        //우리 사이트에서 1년동안 로그인을 안하면 휴먼계정으로의 전환
        //현재 시간-로그인 시간=1년이면 false
        return true;
    }

    @Override
    public String getName() {
        return null;
    }
}