package com.fatec.scelv1;

import java.util.stream.LongStream;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

import com.fatec.scelv1.model.Cliente;
import com.fatec.scelv1.model.ClienteRepository;

@SpringBootApplication
public class Scelv1Application {

	public static void main(String[] args) {
		SpringApplication.run(Scelv1Application.class, args);
	}
	@Bean
	public LocalValidatorFactoryBean validator(MessageSource messageSource) {
		LocalValidatorFactoryBean validatorFactoryBean = new LocalValidatorFactoryBean();
		validatorFactoryBean.setValidationMessageSource(messageSource);
		return validatorFactoryBean;
	}
	@Bean
	CommandLineRunner init(ClienteRepository repository) {
		return args -> {
			repository.deleteAll();
			LongStream.range(1, 10).mapToObj(i -> {
				Cliente c = new Cliente();
				c.setCpf("1111111111" + i);
				c.setNome("Jose" + i);
				c.setEmail("jose" + i + "@email.com");
				c.setEndereco("Rua Sao Paulo" + i);
				c.setCep("04330" + i);
				return c;
			}).map(v -> repository.save(v)).forEach(System.out::println);
		};
	}
	@Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
