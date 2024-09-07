package bj.nazonhou.springsecuritydemystified;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        AuthenticationManager authenticationManager = new ProviderManager(new ServerAuthenticationProvider());

        http.authorizeHttpRequests(
                authorizeHttpRequests -> authorizeHttpRequests
                        .requestMatchers("/api/v1/public").permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(new ServerFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
