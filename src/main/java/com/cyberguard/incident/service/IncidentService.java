package com.cyberguard.incident.service;

import com.cyberguard.incident.dto.IncidentResponse;
import com.cyberguard.incident.entity.Incident;
import com.cyberguard.incident.entity.User;
import com.cyberguard.incident.enums.IncidentSeverity;
import com.cyberguard.incident.enums.IncidentStatus;
import com.cyberguard.incident.enums.Role;
import com.cyberguard.incident.exception.ResourceNotFoundException;
import com.cyberguard.incident.repository.IncidentRepository;
import com.cyberguard.incident.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class IncidentService {

    private final IncidentRepository incidentRepository;
    private final UserRepository userRepository;

    public Page<IncidentResponse> findAll(IncidentStatus status, IncidentSeverity severity, Pageable pageable) {
        Page<Incident> page;
        if (status != null) {
            page = incidentRepository.findByStatus(status, pageable);
        } else if (severity != null) {
            page = incidentRepository.findBySeverity(severity, pageable);
        } else {
            page = incidentRepository.findAll(pageable);
        }
        return page.map(IncidentResponse::from);
    }

    public IncidentResponse findById(Long id) {
        return IncidentResponse.from(getIncidentOrThrow(id));
    }

    @Transactional
    public IncidentResponse updateStatus(Long id, IncidentStatus newStatus) {
        Incident incident = getIncidentOrThrow(id);
        incident.setStatus(newStatus);
        return IncidentResponse.from(incidentRepository.save(incident));
    }

    @Transactional
    public IncidentResponse assignAnalyst(Long id, String analystUsername) {
        Incident incident = getIncidentOrThrow(id);

        User analyst = userRepository.findByUsername(analystUsername)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + analystUsername));

        // Business rule: incidents can only be assigned to staff who are actually
        // authorized to work them, not to a plain USER account.
        if (analyst.getRole() != Role.ADMIN && analyst.getRole() != Role.SECURITY_ANALYST) {
            throw new IllegalArgumentException("Incidents can only be assigned to an ADMIN or SECURITY_ANALYST");
        }

        incident.setAssignedAnalyst(analyst);
        if (incident.getStatus() == IncidentStatus.OPEN) {
            incident.setStatus(IncidentStatus.UNDER_INVESTIGATION);
        }
        return IncidentResponse.from(incidentRepository.save(incident));
    }

    private Incident getIncidentOrThrow(Long id) {
        return incidentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Incident not found: " + id));
    }
}
