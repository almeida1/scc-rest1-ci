package com.fatec.scelv1.servico;

import java.util.List;
import java.util.Optional;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.fatec.scelv1.model.Cliente;
import com.fatec.scelv1.model.ClienteRepository;
import com.fatec.scelv1.model.Endereco;

@Service
public class ClienteServicoI implements ClienteServico {
	Logger logger = LogManager.getLogger(ClienteServicoI.class);
	@Autowired
	ClienteRepository repository;

	@Override
	public ResponseEntity<List<Cliente>> consultaTodos() {
		List<Cliente> clientes = repository.findAll();
		logger.info(">>>>>> 2. servico consulta todos executado");
		return ResponseEntity.ok().body(clientes);
	}

	// https://medium.com/@racc.costa/optional-no-java-8-e-no-java-9-7c52c4b797f1
	// map​ - Se um valor estiver presente retorna um ReponseEntity com o resultado
	// da
	// aplicação da função de mapeamento no valor, caso contrário, retorna um
	// ResponseEntity not foud.
	@Override
	public ResponseEntity<Cliente> consultaPorId(Long id) {
		logger.info(">>>>>> servico consulta por id chamado");
		return repository.findById(id).map(record -> ResponseEntity.ok().body(record))
				.orElse(ResponseEntity.notFound().build());
	}

	public ResponseEntity<Cliente> consultaPorId2(Long id) {
		logger.info(">>>>>> servico consulta por id chamado");
		Optional<Cliente> cliente = repository.findById(id);
		if (cliente.isPresent()) {
			return ResponseEntity.ok().body(cliente.get());
		} else {
			return ResponseEntity.notFound().build();
		}
	}

	public ResponseEntity<Cliente> consultaPorId3(Long id) {
		logger.info(">>>>>> servico consulta por id chamado");
		Optional<Cliente> cliente = repository.findById(id);
		if (cliente.isPresent()) {
			return new ResponseEntity<Cliente>(cliente.get(), HttpStatus.OK);
		} else {
			return ResponseEntity.notFound().build();
		}
	}
	// No Java SE 7 e versões posteriores é possível substituir os tipos
	// de argumentos requeridos na invocação de um construtor de
	// uma classe genérica usando um conjunto vazio (<>)

	@Override
	public ResponseEntity<Object> save(Cliente cliente) {
		Optional<Cliente> umCliente = repository.findByCpf(cliente.getCpf());
		if (umCliente.isPresent()) {
			logger.info(">>>>>> servico save cliente ja cadastrado");
			return new ResponseEntity<>("Cliente já cadastrado", HttpStatus.BAD_REQUEST);
		} else {
			try {
				Endereco endereco = obtemEndereco(cliente.getCep()).getBody();
				if (endereco != null) {
					logger.info(">>>>>> servico save cep valido");
					cliente.setEndereco(endereco.getLogradouro());
					repository.save(cliente);
					return new ResponseEntity<>("Cliente cadastrado", HttpStatus.CREATED);
				} else {
					logger.info(">>>>>> servico save CEP invalido");
					return new ResponseEntity<>("CEP invalido", HttpStatus.BAD_REQUEST);
				}
			} catch (HttpClientErrorException e) {
				logger.error(">>>>>> servico save http exception " + e.getMessage());
				return new ResponseEntity<>("Erro Http exception.", HttpStatus.BAD_REQUEST);
			} catch (Exception e) {
				logger.error(">>>>>> servico save exception não esperada " + e.getMessage());
				return new ResponseEntity<>("Erro não esperado", HttpStatus.BAD_REQUEST);
			}
		}

	}

//	public ResponseEntity<Cliente> atualiza(long id, Cliente cliente) {
//		return repository.findById(id).map(record -> {
//			record.setCpf(cliente.getCpf());
//			record.setNome(cliente.getNome());
//			record.setEmail(cliente.getEmail());
//			record.setCep(cliente.getCep());
//			record.setEndereco(cliente.getEndereco());
//			Cliente updated = repository.save(record);
//			return ResponseEntity.ok().body(updated);
//		}).orElse(ResponseEntity.notFound().build());
//	}
	@Override
	public ResponseEntity<Object> atualiza(long id, Cliente cliente) {
		Optional<Cliente> record = repository.findById(id);

		if (record.isPresent()) {
			record.get().setCpf(cliente.getCpf());
			record.get().setNome(cliente.getNome());
			record.get().setEmail(cliente.getEmail());
			record.get().setCep(cliente.getCep());
			ResponseEntity<Endereco> response = obtemEndereco(cliente.getCep());
			if (response.getStatusCode().equals(HttpStatus.NOT_FOUND)) {
				return new ResponseEntity<>("CEP não localizado", HttpStatus.NOT_FOUND);
			} else {
				record.get().setEndereco(response.getBody().getLogradouro());
				Cliente updated = repository.save(record.get());
				repository.save(updated);
				return new ResponseEntity<>("Cliente atualizado", HttpStatus.OK);
			}
		} else {
			return new ResponseEntity<>("Cliente não cadastrado", HttpStatus.BAD_REQUEST);
		}

	}
	// Um classe que é parametrizada com o ? (Interrogação) representa uma classe de
	// parâmetros
	// de um tipo desconhecido. Dessa forma você pode atribuir a ela qualquer tipo,
	// como String ou Integer.

	public ResponseEntity<?> remover2(Long id) {
		return repository.findById(id).map(record -> {
			repository.deleteById(id);
			return ResponseEntity.ok().build();
		}).orElse(ResponseEntity.notFound().build());
	}

	@Override
	public ResponseEntity<Object> remover(Long id) {
		Optional<Cliente> umCliente = repository.findById(id);
		if (umCliente.isPresent()) {
			repository.deleteById(id);
			return ResponseEntity.ok().build();
		} else {
			return ResponseEntity.notFound().build();
		}
	}

	@Override
	public ResponseEntity<Cliente> consultaPorCpf(String cpf) {
		// return repository.findByCpf(cpf);
		Optional<Cliente> record = repository.findByCpf(cpf);
		if (record.isPresent()) {
			return ResponseEntity.ok().body(record.get());
		} else
			return (ResponseEntity.notFound().build());
	}

	// public ResponseEntity<Endereco> obtemEndereco(String cep) {
	// RestTemplate template = new RestTemplate();

	// String url = "https://viacep.com.br/ws/{cep}/json/";
	// try {
	// ResponseEntity<Endereco> response = template.getForEntity(url,
	// Endereco.class, cep,new ParameterizedTypeReference<Endereco>() {});
	// return response ;
	// } catch (HttpClientErrorException e) {
	// return new ResponseEntity<Endereco>(HttpStatus.BAD_REQUEST);
	// }

	// }
	public ResponseEntity<Endereco> obtemEndereco(String cep) {
		RestTemplate template = new RestTemplate();
		ResponseEntity<Endereco> response = null;
		String url = "https://viacep.com.br/ws/{cep}/json/";
		try {
			response = template.getForEntity(url, Endereco.class, cep, new ParameterizedTypeReference<Endereco>() {
			});
			logger.info(">>>>>> servico obtem endereco " + url + "/" + cep);
			logger.info(">>>>>> servico obtem endereco " + url + "/" + response.getBody());
			if (response.getBody().getLogradouro() != null)
				return response;
			else
				return ResponseEntity.notFound().build();
		} catch (HttpClientErrorException e) {
			logger.info(">>>>>> servico obtem endereco erro " + url + "/" + cep);
			return ResponseEntity.notFound().build();
		}

	}
}
