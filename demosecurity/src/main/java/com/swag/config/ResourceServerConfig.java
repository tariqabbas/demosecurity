package com.swag.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;

@Configuration
@EnableResourceServer
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

//	@Autowired
//	private UserDetailsService userDetailsService;

	@Override
	public void configure(HttpSecurity http) throws Exception { // "/api/v1/**"
//		http.authorizeRequests().antMatchers("/").permitAll().antMatchers("/api/v1/**").authenticated();
		http.anonymous().disable().requestMatchers().antMatchers("/demosecurity/**").and().authorizeRequests()
				.antMatchers("/demosecurity/**").access("hasRole('ADMIN') or hasRole('USER')").and().exceptionHandling()
				.accessDeniedHandler(new OAuth2AccessDeniedHandler());
	}

	
}
