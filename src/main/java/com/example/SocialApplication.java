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

import java.security.Principal;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@SpringBootApplication
@RestController
@EnableOAuth2Client
public class SocialApplication extends WebSecurityConfigurerAdapter {

	@Autowired
	OAuth2ClientContext oauth2ClientContext;

	@RequestMapping("/user")
	public Principal user(Principal principal) {
		return principal;
	}

	@GetMapping("/repositories")
	public ResponseEntity<String> repositories(Principal principal) {

		System.out.println("Principal name: " + principal.toString());

		OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) principal;
		OAuth2AuthenticationDetails oAuth2AuthenticationDetails = (OAuth2AuthenticationDetails) oAuth2Authentication
				.getDetails();

		String url_GET_repositories = "https://api.github.com/user/repos";

		MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
		headers.add("Authorization", String.format("%s %s", oAuth2AuthenticationDetails.getTokenType(), oAuth2AuthenticationDetails.getTokenValue()));
		headers.add("Accept", "application/vnd.github.v3+json");

		RestTemplate restTemplate = new RestTemplate();

		String body = "";
		HttpEntity<String> request = new HttpEntity<String>(body, headers);

		ResponseEntity<String> result = restTemplate.exchange(url_GET_repositories, HttpMethod.GET, request, String.class);
		System.out.println("#### post response = " + result);

		return result;
	}


	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http.antMatcher("/**").authorizeRequests().antMatchers("/", "/login**", "/webjars/**").permitAll().anyRequest()
				.permitAll().and().csrf()
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
		UserInfoTokenServices tokenServices = new UserInfoTokenServices(gitHubResource().getUserInfoUri(),
				gitHub().getClientId());
		tokenServices.setRestTemplate(gitHubTemplate);
		gitHubFilter.setTokenServices(
				new UserInfoTokenServices(gitHubResource().getUserInfoUri(), gitHub().getClientId()));
		return gitHubFilter;
	}

	@Bean
	@ConfigurationProperties("gitHub.client")
	public AuthorizationCodeResourceDetails gitHub() {
		return new AuthorizationCodeResourceDetails();
	}

	@Bean
	@ConfigurationProperties("gitHub.resource")
	public ResourceServerProperties gitHubResource() {
		return new ResourceServerProperties();
	}

}

