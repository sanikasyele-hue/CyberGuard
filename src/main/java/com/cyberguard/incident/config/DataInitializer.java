package com.cyberguard.incident.config;

import com.cyberguard.incident.entity.User;
import com.cyberguard.incident.enums.Role;
import com.cyberguard.incident.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Creates the first ADMIN account on startup so you can log in straight away
 * (self-registration only makes plain USER accounts, which cannot see incidents).
 * Runs only if that username does not exist yet.
 *
 * FOR DEPLOYMENT: set SEED_ADMIN_PASSWORD to your own strong password,
 * or set SEED_ADMIN_ENABLED=false after creating your real admin.
 */
@Component
@RequiredArgsConstructor
public class DataInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);
    private static final String DEFAULT_PASSWORD = "Admin@12345";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.seed.enabled:true}")
    private boolean enabled;

    @Value("${app.seed.admin-username:admin}")
    private String adminUsername;

    @Value("${app.seed.admin-password:" + DEFAULT_PASSWORD + "}")
    private String adminPassword;

    @Value("${app.seed.admin-email:admin@cyberguard.local}")
    private String adminEmail;

    @Override
    public void run(ApplicationArguments args) {
        if (!enabled || userRepository.existsByUsername(adminUsername) || userRepository.existsByEmail(adminEmail)) {
            return;
        }

        userRepository.save(User.builder()
                .username(adminUsername)
                .email(adminEmail)
                .fullName("Default Administrator")
                .password(passwordEncoder.encode(adminPassword))
                .role(Role.ADMIN)
                .enabled(true)
                .build());

        log.warn("Created admin account '{}'.", adminUsername);
        if (DEFAULT_PASSWORD.equals(adminPassword)) {
            log.warn("It uses the DEFAULT password. Set SEED_ADMIN_PASSWORD before deploying anywhere public!");
        }
    }
}
