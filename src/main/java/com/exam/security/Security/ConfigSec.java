package com.exam.security.Security;


import com.exam.security.entities.AppUser;
import com.exam.security.Security.Filter.JwtAuthFilter;
import com.exam.security.Security.Filter.JwtAutorisation;
import com.exam.security.services.IService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.Collection;

@Configuration
@EnableWebSecurity
public class ConfigSec extends WebSecurityConfigurerAdapter {
    private IService iService;

    public ConfigSec(IService iService) {
        this.iService = iService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.formLogin();
        http.authorizeRequests().antMatchers("/h2-console/**", "/refreshToken/**").permitAll();
        http.headers().frameOptions().disable();

        http.authorizeRequests().anyRequest().authenticated();

        http.addFilter(new JwtAuthFilter(authenticationManager()));
        http.addFilterBefore(new JwtAutorisation(), UsernamePasswordAuthenticationFilter.class);

    }

    @Bean
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(username -> {
            AppUser appUser = iService.findUserByUsername(username);
            Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
            appUser.getAppRoles().stream().forEach(r ->{
                grantedAuthorities.add(new SimpleGrantedAuthority(r.getRoleName()));
            });
            return new User(appUser.getUsername(), appUser.getPassword(), grantedAuthorities);
        });

    }
}
