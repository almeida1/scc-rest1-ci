package com.fatec.scelv1.servico;

import java.util.List;
import org.springframework.http.ResponseEntity;
import com.fatec.scelv1.model.Cliente;
import com.fatec.scelv1.model.Endereco;

public interface ClienteServico {
	ResponseEntity<List<Cliente>> consultaTodos();
	ResponseEntity<Cliente> consultaPorCpf(String cpf);
	ResponseEntity<Cliente> consultaPorId(Long id);
	ResponseEntity<Object> save(Cliente cliente);
	ResponseEntity<Object> remover (Long id);
	ResponseEntity<Object> atualiza(long id, Cliente cliente);
	ResponseEntity<Endereco>  obtemEndereco(String cep); 
}
