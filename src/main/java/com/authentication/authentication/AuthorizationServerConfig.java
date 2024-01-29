package com.authentication.authentication;

import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import org.springframework.boot.autoconfigure.security.oauth2.authserver.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.Customizer;
import java.util.UUID;
import AuthorizationGrantType
import com.authentication.authentication.repository.RegisterClientRepository;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {
    
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)throws Exception{
            OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http.formLogin(Customizer.withDefaults()).build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(
            PasswordEncoder passwordEncoder) {
      RegisteredClient registeredClient = RegisteredClient
      .withId(UUID.randomUUID().toString()) .clientId("taco-admin-client")
      .clientSecret(passwordEncoder.encode("secret"))
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
      .redirectUri( "http://127.0.0.1:9090/login/oauth2/code/taco-admin-client")
      .scope("writeIngredients")
      .scope("deleteIngredients")
      .scope(OidcScopes.OPENID)
      .clientSettings(clientSettings -> clientSettings.requireUserConsent(true))
      .build();
        return new InMemoryRegisteredClientRepository(registeredClient); }

    @Bean
     public JWKSource<SecurityContext> jwkSource()
             throws NoSuchAlgorithmException {
                RSAKey rsaKey = generateRsa();
                JWKSet jwkSet = new JWKSet(rsaKey);
                return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
                }
                private static RSAKey generateRsa() throws NoSuchAlgorithmException { KeyPair keyPair = generateRsaKey();
                    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic(); RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate(); return new RSAKey.Builder(publicKey)
                                   .privateKey(privateKey)
                                   .keyID(UUID.randomUUID().toString())
                                   .build();
                    }
                    private static KeyPair generateRsaKey() throws NoSuchAlgorithmException { KeyPairGenerator keyPairGenerator =
                                 KeyPairGenerator.getInstance("RSA");
                                  keyPairGenerator.initialize(2048);
                                  return keyPairGenerator.generateKeyPair();
                    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource); }

}
