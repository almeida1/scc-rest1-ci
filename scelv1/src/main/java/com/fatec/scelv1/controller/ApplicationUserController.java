package com.fatec.scelv1.controller;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fatec.scelv1.model.ApplicationUser;
import com.fatec.scelv1.model.ApplicationUserRepository;

@RestController
@RequestMapping("/users")
public class ApplicationUserController {
	Logger logger = LogManager.getLogger(ApplicationUserController.class);
    private ApplicationUserRepository applicationUserRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    //metodo construtor injecao de dependencia por parametro
    public ApplicationUserController(ApplicationUserRepository applicationUserRepository,
                          BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.applicationUserRepository = applicationUserRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }
    
    //neste exemplo nao controla a entrada de usuarios duplicados

    @PostMapping("/sign-up")
    public void signUp(@RequestBody ApplicationUser user) {
    	logger.info(">>>>>> cadastro de usuario chamado=> " + user.getUsername() );
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        applicationUserRepository.save(user);
    }
}