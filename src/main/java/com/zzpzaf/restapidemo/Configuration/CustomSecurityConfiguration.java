package com.zzpzaf.restapidemo.Configuration;

import java.util.HashMap;
import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
//import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableWebSecurity
@SuppressWarnings("deprecated")
public class CustomSecurityConfiguration {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

                http.authorizeRequests((athReqs) -> athReqs.antMatchers("/api/items").hasRole("USER"))
                    .httpBasic()
                    //.and().authenticationManager(authManager(http))
                    ;
    
                return http.build();
        }

       
        @Bean
        public AuthenticationManager authManager(HttpSecurity http) throws Exception {
               AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
                authenticationManagerBuilder.authenticationProvider(authenticationProvider());
                return authenticationManagerBuilder.build();
        }

        @Bean
        public DaoAuthenticationProvider authenticationProvider(){
            DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
            provider.setPasswordEncoder(passwordEncoder());
            provider.setUserDetailsService(userDetailsService());
            return provider;
            
        }

        @Bean
        public UserDetailsService userDetailsService() {
                UserDetails user = User.builder()
                        .username("usera")
                        .password("{noop}mypassword1")
                        .roles("USER")
                        .build();
                UserDetails admin = User.builder()
                        .username("admin")
                        .password("{noop}mypassword2")
                        .roles("USER", "ADMIN")
                        .build();
                return new InMemoryUserDetailsManager(user, admin);
        }

        
        @SuppressWarnings("deprecation")
        @Bean
        public PasswordEncoder passwordEncoder() {
                Map<String,PasswordEncoder> encoders = new HashMap<>();
                //encoders.put("bcrypt", new BCryptPasswordEncoder());
                //encoders.put("noop", NoOpPasswordEncoder.getInstance());
                   encoders.put("noop",org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance());
                return new DelegatingPasswordEncoder("noop", encoders); 
        }
}

