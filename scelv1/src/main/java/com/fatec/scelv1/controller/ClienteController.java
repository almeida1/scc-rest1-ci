package com.fatec.scelv1.controller;


import java.util.List;


import javax.validation.Valid;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fatec.scelv1.model.Cliente;

import com.fatec.scelv1.servico.ClienteServico;

//definicao dos endpoints
@RestController
@RequestMapping({ "/api" })
public class ClienteController {
	Logger logger = LogManager.getLogger(ClienteController.class);
	@Autowired
	private ClienteServico servico;

	@GetMapping("/v1/clientes")
	//@PreAuthorize("hasRole('ADMIN') or hasRole('BIB')")
	public ResponseEntity<List<Cliente>> findAll() {
		logger.info(">>>>>> 1. controller chamou servico consulta todos");
		return servico.consultaTodos();

	}

	@GetMapping(path = { "/v1/clientes/id/{id}" })
	public ResponseEntity<Cliente> findById(@PathVariable long id) {
		logger.info(">>>>>> 1. controller chamou servico consulta por id");
		return servico.consultaPorId(id);
	}

	@GetMapping(path = { "/v1/clientes/{cpf}" })
	public ResponseEntity<Cliente> findByCpf(@PathVariable String cpf) {
		logger.info(">>>>>> 1. controller chamou servico consultar cpf");
		return servico.consultaPorCpf(cpf);
		
	}

	@PostMapping("/v1/clientes")
	public ResponseEntity<Object> create(@RequestBody @Valid Cliente cliente, BindingResult result) {
		if (result.hasErrors()) {
			logger.info(">>>>>> 1. controller chamou servico save - erro detectado bean validation");
			//result.getFieldError().getDefaultMessage()
			return new ResponseEntity<>(result.getFieldError().getDefaultMessage(), HttpStatus.BAD_REQUEST);
		} else {
			logger.info(">>>>>> 1. controller chamou servico save sem erro no bean validation");
			return servico.save(cliente);
		}

	}

	@PutMapping(value = "/v1/clientes/{id}")
	public ResponseEntity<Object> update(@PathVariable("id") long id, @RequestBody @Valid Cliente cliente) {
		logger.info(">>>>>> 1. controller chamou servico atualiza");
		return servico.atualiza(id, cliente);
	}

	@DeleteMapping(path = { "/v1/clientes/{id}" })
	//@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<?> remover(@PathVariable long id, @AuthenticationPrincipal UserDetails userDetails) {
		logger.info(">>>>>> 1. controller chamou servico remover");
		logger.info(">>>>>> 1.1 usuario logado = " + userDetails);
		return servico.remover(id);
	}
}
