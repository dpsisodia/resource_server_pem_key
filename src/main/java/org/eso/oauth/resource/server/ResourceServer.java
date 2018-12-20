package org.eso.oauth.resource.server;

import java.security.Principal;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
@EnableResourceServer
public class ResourceServer  extends ResourceServerConfigurerAdapter {
	
    public static void main(String[] args) {
        SpringApplication.run(ResourceServer.class, args);
    }
    
    @PreAuthorize("#oauth2.hasAnyScope('read')")
    @RequestMapping(value = "/user", method = RequestMethod.GET)
    public Object user(Principal user) {
    	return user;
    }

    @Value("${jwt.resourceId:http://localhost:8888/api}")
    private String resourceId;
    
    @Value("${public_key}")
    private String publicKey;

    @Bean
	public TokenStore tokenStore() {
		return new JwtTokenStore(tokenEnhancer());
	}

    @Bean
	public JwtAccessTokenConverter tokenEnhancer() {
		JwtAccessTokenConverter converter = new MyJwtAccessTokenConverter();
		converter.setVerifierKey(publicKey);
		return converter;
	}
    
    /**
    * Configure resources
    * Spring OAuth expects "aud" claim in JWT token. That claim's value should match to the resourceId value
    * (if not specified it defaults to "oauth2-resource").
    */
     @Override 
     public void configure(final ResourceServerSecurityConfigurer resources) {
       resources.resourceId(resourceId).tokenStore(tokenStore());
     }

}

@Configuration
@EnableGlobalMethodSecurity
/**
 * To enable oauth2 security expressions on method level. eg:#oauth2.hasAnyScope('read')
 */
class MethodSecurityConfiguration extends GlobalMethodSecurityConfiguration {

  @Override
  protected MethodSecurityExpressionHandler createExpressionHandler() {
    return new OAuth2MethodSecurityExpressionHandler();
  }
}