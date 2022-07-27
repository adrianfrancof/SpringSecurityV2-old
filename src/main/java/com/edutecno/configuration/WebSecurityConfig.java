package com.edutecno.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@EnableWebSecurity
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Autowired
	private AuthenticationSuccessHandler authenticationSuccessHandler;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
//	@Autowired
//	public WebSecurityConfig(AuthenticationSuccessHandler authenticationSuccessHandler) {
//		this.authenticationSuccessHandler = authenticationSuccessHandler;
//	}
	
	@Override
 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
// 		auth.inMemoryAuthentication()
// 		.withUser("correo1@gmail.com")
// 		.password(passwordEncoder().encode("user")).roles("USER")
// 		.and()
// 		.withUser("correo2@gmail.com")
// 		.password(passwordEncoder()
// 		.encode("admin"))
// 		.roles("ADMIN");
 		
 		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
 		
 	}
	
	
 	@Override
 	protected void configure(HttpSecurity http) throws Exception {
// 		http.csrf().disable()
// 		.authorizeRequests()
// 		.antMatchers("/login").permitAll() //se configura la ruta login para ser accedida sin autenticacion
// 		.anyRequest().authenticated() //se configuran las demas rutas para estar aseguradas
// 		.and().formLogin().loginPage("/login").failureUrl("/login?error=true")//pagina de login por defecto y pagina de error
// 		.usernameParameter("user")
// 		.passwordParameter("password")
// 		.defaultSuccessUrl("/"); //sitio de exito post inicio de sesion
 		
// 		http.headers().frameOptions().disable();
 		http
 		.csrf()
 		.disable()
 		.authorizeRequests()
 		.antMatchers("/admin/**").hasAuthority("ADMIN")
 		.antMatchers("/user/**").hasAuthority("USER")
 		.antMatchers("/login")
 		.permitAll() //se configura la ruta login para ser accedida sin autenticacion
 		.anyRequest()
 		.authenticated() //se configuran las demas rutas para estar aseguradas
 		.and()
 		.formLogin()
 		.loginPage("/login")
 		.successHandler(authenticationSuccessHandler)
 		.failureUrl("/login?error=true") //pagina de login por defecto y pagina de error
 		.usernameParameter("email")
 		.passwordParameter("password")
 		//.defaultSuccessUrl("/default",true) //sitio de exito post inicio de sesion
 		.and()
 		.exceptionHandling()
 		.accessDeniedPage("/recurso-prohibido");
 	}
 	
 	//se inicializa bean de encoder de contraseñas
 	@Bean
 	BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();	
 	}
 
}
