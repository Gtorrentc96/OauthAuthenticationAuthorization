/*
 * Copyright 2012-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

import java.security.Principal;
import java.util.Collections;
import java.util.Map;

@SpringBootApplication
@RestController
@EnableOAuth2Client
public class SocialApplication extends WebSecurityConfigurerAdapter {

	private OAuth2ClientContext oauth2ClientContext;
	private OAuth2RestTemplate gitHubRestTemplate;
	private String url_GET_repositories = "https://api.github.com/user/repos";

	@Value("${github.resource.userInfoUri}")
	private String resourceUserInfoUri;

	public SocialApplication(OAuth2ClientContext oauth2ClientContext) {
		this.oauth2ClientContext = oauth2ClientContext;
	}


	@GetMapping("/user")
	public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal) {
	      return Collections.singletonMap("name", principal.getAttribute("name"));
	}

	
	@Autowired
	public void setGitHubRestTemplate(OAuth2RestTemplate gitHubRestTemplate) {
		this.gitHubRestTemplate = gitHubRestTemplate;
	}

	@RequestMapping("/user")
	public Principal user(Principal principal) {
		return principal;
	}

	@GetMapping("/repositories")
	public ResponseEntity<String> repositories(Principal principal) {

		ResponseEntity<String> response;
		response = gitHubRestTemplate.exchange(url_GET_repositories, HttpMethod.GET, null, String.class);

		return response;
	}


	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http.antMatcher("/**").authorizeRequests().antMatchers("/", "/login**", "/webjars/**").permitAll()
				.anyRequest().authenticated().and().csrf()
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
				.addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
		// @formatter:on
	}

	public static void main(String[] args) {
		SpringApplication.run(SocialApplication.class, args);
	}

	@Bean
	public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(filter);
		registration.setOrder(-100);
		return registration;
	}

	private Filter ssoFilter() {
		OAuth2ClientAuthenticationProcessingFilter gitHubFilter = new OAuth2ClientAuthenticationProcessingFilter(
				"/login/gitHub");
		OAuth2RestTemplate gitHubTemplate = new OAuth2RestTemplate(gitHub(), oauth2ClientContext);
		gitHubFilter.setRestTemplate(gitHubTemplate);
		UserInfoTokenServices tokenServices = new UserInfoTokenServices(resourceUserInfoUri,
				gitHub().getClientId());
		tokenServices.setRestTemplate(gitHubTemplate);
		gitHubFilter.setTokenServices(
				new UserInfoTokenServices(resourceUserInfoUri, gitHub().getClientId()));
		return gitHubFilter;
	}

	@GetMapping("/error")
	public String error(HttpServletRequest request) {
		String message = (String) request.getSession().getAttribute("error.message");
		request.getSession().removeAttribute("error.message");
		return message;
	}
	@Bean
	public OAuth2RestTemplate gitHubRestTemplate() {
		return new OAuth2RestTemplate(gitHub(), oauth2ClientContext);
	}

	@Bean
	@ConfigurationProperties("github.client")
	public AuthorizationCodeResourceDetails gitHub() {
		return new AuthorizationCodeResourceDetails();
	}

}

