package akademia;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private PasswordEncoder passwordEncoder;

    public SecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication()
            .passwordEncoder(passwordEncoder)
            .withUser("user")
            .password("$2a$10$atiessYWPXZeCpGdecA8NuIrmnMTYt/fO8MJWtiLPWji9ao9W9qK6")
            .roles("USER")
            .and()
            .withUser("admin")
            .password("$2a$10$Z81hjQ1Vaw.tO8ODeh5aleIOZcvP0lg3mRbdW8tbOwqmPVHfzSGvu")
            .roles("ADMIN", "USER");

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers("/user").hasAnyRole("ADMIN","USER")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .defaultSuccessUrl("/");
    }
}

