// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep;

/**
 * What the PEP is doing, for a host's health page. Holds no secret.
 * Times are milliseconds, or null until the thing has happened (and while
 * the background work is not running, for the {@code until} ones).
 */
public final class Status {
    public String name;
    public Mode mode;
    public String application;
    public boolean registered;
    public boolean running;
    /** {@code local}: a compiled set is held. */
    public boolean holdsPolicy;
    public int policyCount;
    public String syncToken;
    public long decisions;
    public long allowed;
    public long refused;
    public long unavailable;
    public long undischargeable;
    public int recordsQueued;
    public String keyThumbprint;
    /**
     * The current problems, one per area (registration, pull, heartbeat,
     * records, key), joined. Empty when there are none.
     */
    public String lastError;

    /** The service's base URL, the realm prefix included. */
    public String pdpUrl;
    public int protocolVersion;
    /** What the host's signal stream carries, as the heartbeat reports it. */
    public EventStream eventStream;

    /** Since {@code start}. */
    public Long uptime;
    /**
     * Since what the PEP holds last changed: a new policy set or catalogue
     * ({@code local}), a new catalogue ({@code central}).
     */
    public Long sincePolicyUpdate;
    /** Since the last pull that succeeded, changed or {@code 304}. */
    public Long sinceLastPull;
    /**
     * Until the next scheduled pull. An event, or a heartbeat saying the
     * PEP is stale, pulls sooner.
     */
    public Long untilNextPull;
    public Long sinceLastHeartbeat;
    public Long untilNextHeartbeat;
    /** Since the last {@code pep-policies-changed} event acted on. */
    public Long sinceLastEvent;

    /** The catalogue's sync token. */
    public String catalogueToken;
    /** Subject properties the catalogue declares (the claims that are sent). */
    public int catalogueSubjectProperties;

    public long pulls;
    /** Pulls that brought something new. The rest were {@code 304}. */
    public long pullsChanged;
    public long pullFailures;
    public long heartbeats;
    public long heartbeatFailures;
    public long registrations;
    public long eventsReceived;
    /** Events naming another PEP. */
    public long eventsIgnored;
    public long recordsShipped;
    /** Records dropped because the queue was full. */
    public long recordsDropped;
    /** {@code central}: Permits held in the cache now. */
    public int permitCacheEntries;
    /** {@code central}: decisions the cache answered. */
    public long permitCacheHits;
    /**
     * The decisions' mean and slowest time, in microseconds.
     * {@code central} includes the round trip; {@code local} the PIP, if asked.
     */
    public long meanDecisionMicros;
    public long maxDecisionMicros;
}
