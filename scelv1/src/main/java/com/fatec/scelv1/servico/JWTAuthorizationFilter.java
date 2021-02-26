package com.fatec.scelv1.servico;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
/*
 * Este filtro verificará a existência e validade do token de acesso no cabeçalho de autorização.
 * Os endpoints que estarão sujeitos a esse filtro sao especificados na classe configuracao web do Spring Boot
 */
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
	private JWTUtil jwtUtil;

	private UserDetailsService userDetailsService; // instacia UserDetailsSevericeImpl
	Logger logger = LogManager.getLogger(JWTAuthorizationFilter.class);
	public JWTAuthorizationFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil,
			UserDetailsService userDetailsService) {
		super(authenticationManager);
		logger.info(">>>>>> JWT Authorization filter chamado => ");
		this.jwtUtil = jwtUtil;
		this.userDetailsService = userDetailsService;
	}
/*
 * O método doFilterInternal intercepta as solicitações e verifica o cabeçalho de autorização. 
 * Se o cabeçalho não estiver presente ou não começar com “BEARER”, ele segue para a cadeia de filtros.
 * Se o cabeçalho estiver presente, o método getAuthentication é chamado e verifica, 
 * se o token é válido, ele retorna um token de acesso que Spring usará internamente.
 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String header = request.getHeader("Authorization");
		if (header != null && header.startsWith("Bearer ")) {
			UsernamePasswordAuthenticationToken auth = getAuthentication(header.substring(7));
			if (auth != null) {
				SecurityContextHolder.getContext().setAuthentication(auth);
			}
		}
		chain.doFilter(request, response);
	}
	private UsernamePasswordAuthenticationToken getAuthentication(String token) {
		if (jwtUtil.tokenValido(token)) {
			String username = jwtUtil.getUsername(token);
			UserDetails user = userDetailsService.loadUserByUsername(username);
			return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
		}
		return null;
	}
}
