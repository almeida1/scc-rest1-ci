package com.fatec.scelv1.servico;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.fatec.scelv1.controller.ClienteController;
import com.fatec.scelv1.model.ApplicationUser;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

/**
 * Esta classe estende UsernamePasswordAuthenticationFilter, que é a classe padrão 
 * para autenticação de senha no Spring Security. Esta classe permite personalisar 
 * a lógica de autenticação.
 * Pode-se definir no construtor uma chamada ao método setFilterProcessesUrl. Este método 
 * define o URL de login padrão para o parâmetro fornecido. 
 * Neste exemplo nao foi definido um construtor, portanto o Spring Security cria o endpoint “/login” 
 * por padrão.
 * @author almeida
 *
 */

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    
	private JWTUtil jwtUtil;
	private AuthenticationManager authenticationManager;
	User user; //spring framework security
	Logger logger = LogManager.getLogger(JWTAuthenticationFilter.class);
    
	public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil) {
		logger.info(">>>>>> JWT Authentication filter chamado => ");
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }
	/**
	* A função tentativa de autenticacao é executada quando o usuário da aplicação tenta efetuar login 
	* na aplicação. Ele lê as credenciais, cria um POJO do usuário a partir delas e, em seguida, 
	* verifica as credenciais para autenticar.
	* O nome de usuário, a senha e uma lista vazia sao passados como parametro. A lista vazia 
	* representa a autorizacao (funções liberadas para o usuario) 
	* neste exemplo um usuario autenticado esta autorizado a utilizar todas as funcoes.
	* Se a autenticação for bem-sucedida, o método successfulAuthentication é executado. 
	* Os parâmetros desse método são passados pelo Spring Security nos bastidores.
	*/
    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
                                                HttpServletResponse res) throws AuthenticationException {
       logger.info(">>>>>> tentativa de autenticacao => ");
    	try {
            ApplicationUser creds = new ObjectMapper().readValue(req.getInputStream(), ApplicationUser.class);

            return this.authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            creds.getUsername(),
                            creds.getPassword(),
                            new ArrayList<>())
            );
            
        } catch (IOException e) {
        	logger.info(">>>>>> erro na tentativa de autenticacao => ");
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {
    	logger.info(">>>>>> sucesso na tentativa de autenticacao => ");
    	String username = ((User) auth.getPrincipal()).getUsername();
    	logger.info(">>>>>> user => " + username);
    	String token = jwtUtil.generateToken(username);
    	logger.info(">>>>>> token => " + token);
    	res.addHeader("Authorization","Bearer " + token);
    	//res.addHeader("access-control-expose-headers", "Authorization");
    	
        
                
 	}
    
}