package com.cos.security1.config.auth;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
    private final UserRepository userRepository;
    @Override
    //form에서 username으로 와야 받아진다.
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseGet(()->new User());
        if(user.getId()!=null){
            return new PrincipalDetails(user);
        }else {
            //없다는 의미가 회원가입이 안되어 있다는 의미이다.
            //여기다가 로그인 실패시 로직을 짜거나 하면 된다.
            return null;
        }
    }
}
