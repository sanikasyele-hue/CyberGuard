package com.cyberguard.incident.event;

/** Published by the detection engine whenever it creates a new incident. */
public record IncidentCreatedEvent(Long incidentId) {
}
