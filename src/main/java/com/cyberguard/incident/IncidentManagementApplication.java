package com.cyberguard.incident;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync // lets AI analysis run in the background after an upload
public class IncidentManagementApplication {
    public static void main(String[] args) {
        SpringApplication.run(IncidentManagementApplication.class, args);
    }
}
