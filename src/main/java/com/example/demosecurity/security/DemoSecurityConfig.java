package com.example.demosecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class DemoSecurityConfig {

    /*@Bean
    public InMemoryUserDetailsManager userDetailsManager() {
        UserDetails A = User.builder().username("Aaa").password("{noop}aaa").roles("EMPLOYEE").build();
        UserDetails B = User.builder().username("Bbb").password("{noop}bbb").roles("EMPLOYEE", "MANAGER").build();
        UserDetails C = User.builder().username("Ccc").password("{noop}ccc").roles("EMPLOYEE", "MANAGER", "ADMIN").build();
        return new InMemoryUserDetailsManager(A, B, C);
    }*/

    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource){
        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
        userDetailsManager.setUsersByUsernameQuery("select username, password, enabled from users1 where username=?");
        userDetailsManager.setAuthoritiesByUsernameQuery("select username, authority from authorities1 where username=?");
        return userDetailsManager;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests(config ->
                        config
                                .requestMatchers("/").hasRole("EMPLOYEE")
                                .requestMatchers("/leaders/**").hasRole("MANAGER")
                                .requestMatchers("/systems/**").hasRole("ADMIN")
                                .anyRequest().authenticated())
                .formLogin(form -> form.loginPage("/showMyLoginPage").loginProcessingUrl("/authenticateTheUser").permitAll())
                .logout(LogoutConfigurer::permitAll)
                .exceptionHandling(config -> config.accessDeniedPage("/access-denied"));

        return httpSecurity.build();
    }

    /* @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.authorizeHttpRequests(config->
                config.requestMatchers(HttpMethod.GET,"/api/employees").hasRole("EMPLOYEE")
                        .requestMatchers(HttpMethod.GET,"/api/employees/**").hasRole("EMPLOYEE")
                        .requestMatchers(HttpMethod.POST,"/api/employees").hasRole("MANAGER")
                        .requestMatchers(HttpMethod.PUT,"/api/employees").hasRole("MANAGER")
                        .requestMatchers(HttpMethod.DELETE,"/api/employees/**").hasRole("ADMIN"));
        httpSecurity.httpBasic(Customizer.withDefaults());
        httpSecurity.csrf(AbstractHttpConfigurer::disable);
        return httpSecurity.build();
    }*/

}
