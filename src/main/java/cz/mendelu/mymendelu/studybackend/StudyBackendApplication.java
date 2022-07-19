package cz.mendelu.mymendelu.studybackend;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

import java.util.Arrays;

@SpringBootApplication
public class StudyBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(StudyBackendApplication.class, args);
	}

}
