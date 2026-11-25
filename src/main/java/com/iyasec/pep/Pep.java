// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.iyasec.pep.authzen.Trusted;
import com.iyasec.pep.credential.Audience;
import com.iyasec.pep.credential.Credential;
import com.iyasec.pep.http.Body;
import com.iyasec.pep.http.HttpClient;
import com.iyasec.pep.key.SigningKey;
import com.iyasec.pep.local.Local;
import com.iyasec.pep.records.Records;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * The embedded PEP: its lifecycle, the control plane, and {@code decide}.
 * {@link #create} reads the configuration and the key and sends nothing.
 * {@link #decide} never fails: a decision it cannot make is {@code Unavailable}.
 */
public final class Pep implements AutoCloseable {
    /** The PEP protocol version this package speaks. */
    public static final int PROTOCOL_VERSION = 1;
    /**
     * The Shared Signals event type that says the bound application's
     * policies or the catalogue changed.
     */
    public static final String POLICIES_CHANGED_EVENT = "urn:iya:sts:secevent:event-type:pep-policies-changed";

    private static final String VERSION = HttpClient.USER_AGENT;
    private static final long RECORDS_NS = 5_000_000_000L;
    private static final long KEY_CHECK_NS = 30_000_000_000L;
    private static final long TICK_NS = 1_000_000_000L;
    private static final long REGISTER_FIRST_NS = 2_000_000_000L;

    private final PepConfig config;
    private final Credential credential;
    private final Records records;
    private final AtomicBoolean registered = new AtomicBoolean();
    private final AtomicBoolean serviceFailing = new AtomicBoolean();
    private final Counters counters = new Counters();
    private final Object timingLock = new Object();
    private final Timing timing = new Timing();
    private final Object problemsLock = new Object();
    private final TreeMap<String, String> problems = new TreeMap<>();
    private final Object streamLock = new Object();
    private EventStream eventStream;
    private final Wake wake = new Wake();
    private final Object permitsLock = new Object();
    private final Map<String, CachedPermit> permits = new HashMap<>();
    private final Object rootsLock = new Object();
    private String catalogueToken = "";
    private Set<String> subjectRoots = new HashSet<>();
    private final Object identityLock = new Object();
    private String identity = "";
    private final Object heldLock = new Object();
    private Local.Held held;
    private final Object workerLock = new Object();
    private Thread worker;

    private Pep(PepConfig config, Credential credential) {
        this.config = config;
        this.credential = credential;
        this.records = new Records(SigningKey.randomId());
        this.eventStream = config.signals ? EventStream.DOWN : EventStream.NONE;
    }

    /** Checks the configuration and reads the key. Sends nothing. */
    public static Pep create(PepConfig config) throws PepException {
        if (config == null) {
            throw new PepException("config", "pep must be an object");
        }
        config.validate();
        HttpClient client = HttpClient.create(config.tlsCa, Duration.ofMillis(config.timeoutMs));
        return new Pep(config, Credential.create(config, client));
    }

    /** The configuration in force. */
    public PepConfig config() {
        return config;
    }

    /** The PEP key's RFC 7638 thumbprint. */
    public String keyThumbprint() {
        return credential.thumbprint();
    }

    /**
     * Reads the key file again now. A changed key drops every token.
     * A file that no longer holds a usable key keeps the one held and is an error.
     *
     * @return whether the key changed
     */
    public boolean reloadKey() throws PepException {
        return credential.reloadKey();
    }

    /**
     * Starts the background work. The first registration and the first pull
     * run before this returns. An unreachable service is retried in the background.
     */
    public void start() throws PepException {
        synchronized (workerLock) {
            if (worker != null) {
                return;
            }
            synchronized (wake) {
                wake.stop = false;
            }
            synchronized (timingLock) {
                timing.started = System.nanoTime();
            }
            register();
            pull();
            Thread thread = new Thread(this::run, "iya-pep " + config.name);
            thread.setDaemon(true);
            try {
                thread.start();
            } catch (RuntimeException e) {
                throw new PepException("config", "the PEP's thread could not start: " + e.getMessage());
            }
            worker = thread;
        }
    }

    /** Stops the background work and waits for it. Queued records are sent once more first. */
    public void stop() {
        Thread thread;
        synchronized (workerLock) {
            thread = worker;
            worker = null;
        }
        if (thread == null) {
            return;
        }
        synchronized (wake) {
            wake.stop = true;
            wake.notifyAll();
        }
        try {
            thread.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public void close() {
        stop();
    }

    /**
     * Decides one access. Never fails: what cannot be decided is {@code Unavailable}.
     * A fault on the decision path is recorded and returned as {@code Unavailable}.
     */
    public Decision decide(Subject subject, Access access) {
        long began = System.nanoTime();
        Decision decision = guarded(
                () -> config.mode == Mode.CENTRAL ? decideCentral(subject, access) : decideLocal(subject, access),
                why -> note("decide", why));
        long micros = (System.nanoTime() - began) / 1_000L;
        if (micros < 0) {
            micros = Long.MAX_VALUE;
        }
        counters.decisionMicrosTotal.addAndGet(micros);
        counters.decisionMicrosMax.accumulateAndGet(micros, Math::max);
        counters.decisions.incrementAndGet();
        switch (decision.kind()) {
            case PERMIT -> counters.allowed.incrementAndGet();
            case DENY -> counters.refused.incrementAndGet();
            case UNAVAILABLE -> counters.unavailable.incrementAndGet();
        }
        return decision;
    }

    /**
     * Hands over a verified {@code pep-policies-changed} event. The event is
     * only a hint: the pull uses this PEP's own token. An event naming another
     * PEP is ignored.
     *
     * @return whether it was acted on
     */
    public boolean onPolicyEvent(JsonNode payload) {
        if (payload != null) {
            JsonNode pep = payload.get("pep");
            if (pep != null && pep.isTextual() && !pep.asText().equals(config.name)) {
                counters.eventsIgnored.incrementAndGet();
                return false;
            }
        }
        counters.eventsReceived.incrementAndGet();
        synchronized (timingLock) {
            timing.lastEvent = System.nanoTime();
        }
        synchronized (permitsLock) {
            permits.clear();
        }
        synchronized (wake) {
            wake.pull = true;
            wake.notifyAll();
        }
        return true;
    }

    /** Tells the PEP what the host's signal stream can deliver, for the heartbeat. */
    public void setEventStream(EventStream state) {
        synchronized (streamLock) {
            eventStream = state == null ? EventStream.NONE : state;
        }
    }

    /** Pulls now and waits for it. */
    public void pullNow() throws PepException {
        pullCounted();
    }

    /** What the PEP is doing. Holds no secret. */
    public Status status() {
        boolean running;
        synchronized (workerLock) {
            running = worker != null;
        }
        Local.Held current;
        synchronized (heldLock) {
            current = held;
        }
        boolean holdsPolicy = current != null;
        int policyCount = current == null ? 0 : current.policies.size();
        String syncToken = current == null ? "" : current.policyToken;
        String catalogue;
        int catalogueProperties;
        if (current != null) {
            catalogue = current.catalogueToken;
            Set<String> roots = new HashSet<>();
            for (com.iyasec.pep.authzen.Row row : current.catalogue.rows) {
                if ("subject".equals(row.object)) {
                    roots.add(Bodies.rootOf(row.property));
                }
            }
            catalogueProperties = roots.size();
        } else {
            synchronized (rootsLock) {
                catalogue = catalogueToken;
                catalogueProperties = subjectRoots.size();
            }
        }
        long decisions = counters.decisions.get();
        long[] shipped = records.counts();
        Status status = new Status();
        status.name = config.name;
        status.mode = config.mode;
        status.application = config.application;
        status.registered = registered.get();
        status.running = running;
        status.holdsPolicy = holdsPolicy;
        status.policyCount = policyCount;
        status.syncToken = syncToken;
        status.decisions = decisions;
        status.allowed = counters.allowed.get();
        status.refused = counters.refused.get();
        status.unavailable = counters.unavailable.get();
        status.undischargeable = counters.undischargeable.get();
        status.recordsQueued = records.queued();
        status.keyThumbprint = credential.thumbprint();
        synchronized (problemsLock) {
            status.lastError = String.join("; ", problems.values());
        }
        status.pdpUrl = config.base();
        status.protocolVersion = PROTOCOL_VERSION;
        synchronized (streamLock) {
            status.eventStream = eventStream;
        }
        long now = System.nanoTime();
        synchronized (timingLock) {
            status.uptime = since(timing.started, now);
            status.sincePolicyUpdate = since(timing.lastChange, now);
            status.sinceLastPull = since(timing.lastPull, now);
            status.untilNextPull = running ? until(timing.nextPull, now) : null;
            status.sinceLastHeartbeat = since(timing.lastHeartbeat, now);
            status.untilNextHeartbeat = running ? until(timing.nextHeartbeat, now) : null;
            status.sinceLastEvent = since(timing.lastEvent, now);
        }
        status.catalogueToken = catalogue;
        status.catalogueSubjectProperties = catalogueProperties;
        status.pulls = counters.pulls.get();
        status.pullsChanged = counters.pullsChanged.get();
        status.pullFailures = counters.pullFailures.get();
        status.heartbeats = counters.heartbeats.get();
        status.heartbeatFailures = counters.heartbeatFailures.get();
        status.registrations = counters.registrations.get();
        status.eventsReceived = counters.eventsReceived.get();
        status.eventsIgnored = counters.eventsIgnored.get();
        status.recordsShipped = shipped[0];
        status.recordsDropped = shipped[1];
        synchronized (permitsLock) {
            status.permitCacheEntries = permits.size();
        }
        status.permitCacheHits = counters.permitCacheHits.get();
        status.meanDecisionMicros = decisions == 0 ? 0 : counters.decisionMicrosTotal.get() / decisions;
        status.maxDecisionMicros = counters.decisionMicrosMax.get();
        return status;
    }

    /** A fault while deciding becomes {@code Unavailable} and is handed to {@code note}. */
    static Decision guarded(Supplier<Decision> decide, Consumer<String> note) {
        try {
            return decide.get();
        } catch (Throwable thrown) {
            String what = thrown.getMessage();
            if (what == null || what.isEmpty()) {
                what = "a panic";
            }
            String why = "the PEP failed while deciding: " + what;
            note.accept(why);
            return Decision.unavailable(why);
        }
    }

    private void run() {
        long now = System.nanoTime();
        long nextHeartbeat = now;
        long nextRecords = now + RECORDS_NS;
        long nextKey = now + KEY_CHECK_NS;
        long nextRegister = now;
        long registerRetry = REGISTER_FIRST_NS;
        long registerRetryMax = Math.max(config.heartbeatIntervalMs * 1_000_000L, REGISTER_FIRST_NS);
        long nextPull = now + pollPeriodNs();
        while (true) {
            boolean pullAsked;
            synchronized (wake) {
                long deadline = System.nanoTime() + TICK_NS;
                while (!wake.stop && !wake.pull && System.nanoTime() < deadline) {
                    long remain = deadline - System.nanoTime();
                    if (remain <= 0) {
                        break;
                    }
                    long millis = remain / 1_000_000L;
                    int nanos = (int) (remain % 1_000_000L);
                    if (millis == 0 && nanos == 0) {
                        break;
                    }
                    try {
                        wake.wait(millis, nanos);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
                if (wake.stop) {
                    break;
                }
                pullAsked = wake.pull;
                wake.pull = false;
            }
            now = System.nanoTime();
            if (now >= nextKey) {
                nextKey = now + KEY_CHECK_NS;
                try {
                    credential.reloadKey();
                    note("key", "");
                } catch (PepException e) {
                    note("key", "the assertion key: " + e.getMessage());
                }
            }
            if (!registered.get() && now >= nextRegister) {
                register();
                if (registered.get()) {
                    registerRetry = REGISTER_FIRST_NS;
                } else {
                    nextRegister = now + registerRetry;
                    registerRetry = Math.min(registerRetry * 2, registerRetryMax);
                }
            }
            long period = pollPeriodNs();
            if (nextPull > now + period) {
                nextPull = now + period;
            }
            boolean pullDue = pullAsked || now >= nextPull;
            if (now >= nextHeartbeat) {
                nextHeartbeat = now + config.heartbeatIntervalMs * 1_000_000L;
                pullDue = heartbeat() || pullDue;
            }
            if (pullDue) {
                nextPull = System.nanoTime() + pollPeriodNs();
                pull();
            }
            if (now >= nextRecords) {
                nextRecords = now + RECORDS_NS;
                shipRecords();
            }
            synchronized (timingLock) {
                timing.nextPull = nextPull;
                timing.nextHeartbeat = nextHeartbeat;
            }
        }
        shipRecords();
    }

    private long pollPeriodNs() {
        EventStream state;
        synchronized (streamLock) {
            state = eventStream;
        }
        long millis = state == EventStream.REQUESTED ? config.fallbackPollMs : config.pollIntervalMs;
        return millis * 1_000_000L;
    }

    private String caller() {
        synchronized (identityLock) {
            if (identity == null || identity.isEmpty()) {
                return config.name;
            }
            return identity;
        }
    }

    private void note(String area, String problem) {
        synchronized (problemsLock) {
            if (problem == null || problem.isEmpty()) {
                problems.remove(area);
            } else {
                problems.put(area, problem);
            }
        }
    }

    private ObjectNode identityBody() {
        ObjectNode body = Json.object();
        body.put("name", config.name);
        body.put("kind", "embedded");
        body.put("application", config.application);
        body.put("mode", config.mode.asString());
        body.put("protocolVersion", PROTOCOL_VERSION);
        body.put("version", VERSION);
        return body;
    }

    private void register() {
        String url = config.base() + "/xacml/pep/register";
        try {
            var answer = credential.call(Audience.PEP, "POST", url, "application/json", List.of(), Body.json(identityBody()));
            if (answer.status == 200 || answer.status == 201) {
                JsonNode json = answer.json();
                if (json != null && json.path("identity").isTextual() && !json.get("identity").asText().isEmpty()) {
                    synchronized (identityLock) {
                        identity = json.get("identity").asText();
                    }
                }
                counters.registrations.incrementAndGet();
                registered.set(true);
                note("register", "");
            } else {
                JsonNode json = answer.json();
                String error = json != null && json.path("error").isTextual() ? json.get("error").asText() : "";
                String description = json != null && json.path("error_description").isTextual()
                        ? json.get("error_description").asText() : "";
                note("register", "registration answered " + answer.status + " " + error + " " + description);
            }
        } catch (PepException e) {
            note("register", "registration: " + e.getMessage());
        }
    }

    /** A call to the service failed. Cached Permits are dropped until an evaluation succeeds. */
    private void serviceFailed() {
        if (config.mode == Mode.CENTRAL && config.permitCacheMs > 0) {
            serviceFailing.set(true);
            synchronized (permitsLock) {
                permits.clear();
            }
        }
    }

    /** @return whether the service says the PEP is not current */
    private boolean heartbeat() {
        String url = config.base() + "/xacml/pep/heartbeat";
        ObjectNode body = identityBody();
        synchronized (heldLock) {
            if (held != null) {
                body.put("syncToken", held.policyToken);
                body.put("policyCount", held.policies.size());
            }
        }
        body.put("decisions", counters.decisions.get());
        body.put("allowed", counters.allowed.get());
        body.put("refused", counters.refused.get() + counters.unavailable.get());
        body.put("undischargeable", counters.undischargeable.get());
        synchronized (streamLock) {
            body.put("policyEvents", eventStream.asString());
        }
        com.iyasec.pep.http.Answer answer;
        try {
            answer = credential.call(Audience.PEP, "POST", url, "application/json", List.of(), Body.json(body));
        } catch (PepException e) {
            counters.heartbeatFailures.incrementAndGet();
            serviceFailed();
            note("heartbeat", "the heartbeat: " + e.getMessage());
            return false;
        }
        if (answer.status == 200) {
            counters.heartbeats.incrementAndGet();
            synchronized (timingLock) {
                timing.lastHeartbeat = System.nanoTime();
            }
            note("heartbeat", "");
            JsonNode json = answer.json();
            return json != null && json.path("current").isBoolean() && !json.get("current").booleanValue();
        }
        counters.heartbeatFailures.incrementAndGet();
        if (answer.status == 404) {
            registered.set(false);
            return false;
        }
        serviceFailed();
        note("heartbeat", "the heartbeat answered " + answer.status);
        return false;
    }

    private boolean pullResult() throws PepException {
        if (config.mode == Mode.LOCAL) {
            Local.Held current;
            synchronized (heldLock) {
                current = held;
            }
            Local.Pull fresh = Local.pull(credential, config.base(), config.name, current);
            if (fresh.held != null) {
                synchronized (heldLock) {
                    held = fresh.held;
                }
            }
            return fresh.changed;
        }
        String token;
        synchronized (rootsLock) {
            token = catalogueToken;
        }
        Bodies.Fresh fresh = Bodies.pullSubjectRoots(credential, config.base(), token);
        if (fresh != null) {
            synchronized (rootsLock) {
                catalogueToken = fresh.token;
                subjectRoots = fresh.roots;
            }
        }
        return fresh != null;
    }

    private boolean pullCounted() throws PepException {
        try {
            boolean changed = pullResult();
            long now = System.nanoTime();
            counters.pulls.incrementAndGet();
            synchronized (timingLock) {
                timing.lastPull = now;
                if (changed) {
                    counters.pullsChanged.incrementAndGet();
                    timing.lastChange = now;
                }
            }
            return changed;
        } catch (PepException e) {
            counters.pullFailures.incrementAndGet();
            throw e;
        }
    }

    private void pull() {
        try {
            pullCounted();
            note("pull", "");
        } catch (PepException e) {
            note("pull", "the pull: " + e.getMessage());
        }
    }

    private void shipRecords() {
        if (records.queued() == 0) {
            return;
        }
        String url = config.base() + "/admin-api/pep-audit";
        try {
            records.ship(credential, url);
            note("records", "");
        } catch (PepException e) {
            note("records", "the decision records: " + e.getMessage());
        }
    }

    private Decision decideCentral(Subject subject, Access access) {
        Set<String> roots;
        synchronized (rootsLock) {
            roots = subjectRoots;
        }
        ObjectNode body = Bodies.evaluationBody(declaredOnly(subject, roots), access, config.application, config.supportedObligations);
        long cacheFor = config.permitCacheMs;
        String cacheKey = body.toString();
        if (cacheFor > 0 && !serviceFailing.get()) {
            synchronized (permitsLock) {
                CachedPermit cached = permits.get(cacheKey);
                if (cached != null) {
                    long elapsed = (System.nanoTime() - cached.at) / 1_000_000L;
                    if (elapsed < cacheFor) {
                        counters.permitCacheHits.incrementAndGet();
                        return cached.decision.copy();
                    }
                    permits.remove(cacheKey);
                }
            }
        }
        String url = config.base() + "/access/v1/evaluation";
        com.iyasec.pep.http.Answer answer;
        try {
            answer = credential.call(Audience.ACCESS, "POST", url, "application/json", List.of(), Body.json(body));
        } catch (PepException e) {
            serviceFailed();
            return Decision.unavailable("the service could not be asked: " + e.getMessage());
        }
        JsonNode json = answer.json();
        if (json == null) {
            json = Json.MAPPER.nullNode();
        }
        Decision decision;
        JsonNode said = json.get("decision");
        if (answer.status == 200 && said != null && said.isBoolean() && said.booleanValue()) {
            List<Obligation> obligations = new ArrayList<>();
            JsonNode list = json.path("context").path("obligations");
            if (list.isArray()) {
                for (JsonNode item : list) {
                    Obligation obligation = Bodies.obligationFrom(item);
                    if (obligation != null) {
                        obligations.add(obligation);
                    }
                }
            }
            List<Obligation> advice = new ArrayList<>();
            JsonNode adviceList = json.path("context").path("advice");
            if (adviceList.isArray()) {
                for (JsonNode item : adviceList) {
                    Obligation obligation = Bodies.adviceFrom(item);
                    if (obligation != null) {
                        advice.add(obligation);
                    }
                }
            }
            decision = Decision.permit(obligations, advice);
        } else if (answer.status == 200 && said != null && said.isBoolean()) {
            JsonNode undischargeable = json.path("context").path("undischargeable_obligations");
            if (undischargeable.isArray() && !undischargeable.isEmpty()) {
                counters.undischargeable.incrementAndGet();
            }
            String why = reason(json);
            decision = Decision.deny(why == null ? "the service denied the access" : why);
        } else if (answer.status == 400) {
            String error = textual(json, "error");
            if (error.isEmpty()) {
                error = textual(json, "code");
            }
            String description = textual(json, "error_description");
            if (description.isEmpty()) {
                description = textual(json, "message");
            }
            decision = Decision.deny(("the service refused the evaluation: " + error + " " + description).stripTrailing());
        } else {
            serviceFailed();
            decision = Decision.unavailable("the service answered " + answer.status + " to the evaluation");
        }
        if (decision.kind() != Decision.Kind.UNAVAILABLE) {
            serviceFailing.set(false);
        }
        if (cacheFor > 0 && decision.isPermit()) {
            synchronized (permitsLock) {
                permits.put(cacheKey, new CachedPermit(System.nanoTime(), decision.copy()));
            }
        }
        return decision;
    }

    private Decision decideLocal(Subject subject, Access access) {
        Local.Held current;
        synchronized (heldLock) {
            current = held;
        }
        if (current == null) {
            return Decision.unavailable("no policy is held yet");
        }
        Set<String> roots = new HashSet<>();
        for (com.iyasec.pep.authzen.Row row : current.catalogue.rows) {
            if ("subject".equals(row.object)) {
                roots.add(Bodies.rootOf(row.property));
            }
        }
        ObjectNode body = Bodies.evaluationBody(declaredOnly(subject, roots), access, config.application, config.supportedObligations);
        boolean fga = current.catalogue.fgaApplications.contains(config.application);
        Trusted trusted = new Trusted(config.realm(), caller(), config.application, fga);
        Local.Made made = Local.decide(credential, config.base(), current, body, trusted,
                subject.id, "application".equals(subject.kind), Instant.now());
        if (made.outcome != null) {
            if (!made.outcome.undischargeable.isEmpty()) {
                counters.undischargeable.incrementAndGet();
            }
            if (config.decisionRecords) {
                ObjectNode record = Json.object();
                record.put("kind", "authzen");
                record.put("endpoint", "evaluation");
                record.put("decision", made.outcome.xacmlDecision.asString());
                record.put("allowed", made.decision.isPermit());
                record.put("fault", made.outcome.fault);
                record.put("subject", subject.id);
                record.put("subjectType", subject.kind);
                record.put("resource", access.resourceType + ":" + access.resourceId);
                record.put("action", access.action);
                record.put("application", config.application);
                record.put("caller", config.name);
                record.put("bias", "deny-biased");
                record.put("why", made.outcome.why);
                record.set("discharged", Json.strings(made.outcome.discharged));
                record.set("undischargeable", Json.strings(made.outcome.undischargeable));
                records.push(record);
            }
        }
        return made.decision;
    }

    private static Subject declaredOnly(Subject subject, Set<String> roots) {
        Subject out = new Subject();
        out.kind = subject == null || subject.kind == null ? "" : subject.kind;
        out.id = subject == null || subject.id == null ? "" : subject.id;
        out.properties = new LinkedHashMap<>();
        if (subject != null && subject.properties != null && roots != null) {
            for (Map.Entry<String, JsonNode> entry : subject.properties.entrySet()) {
                if (roots.contains(entry.getKey())) {
                    out.properties.put(entry.getKey(), entry.getValue());
                }
            }
        }
        return out;
    }

    private static String reason(JsonNode json) {
        JsonNode context = json.get("context");
        if (context == null || !context.isObject()) {
            return null;
        }
        for (String key : new String[] {"reason_admin", "reason_user"}) {
            JsonNode value = context.get(key);
            if (value == null) {
                continue;
            }
            if (value.isTextual()) {
                if (!value.asText().isEmpty()) {
                    return value.asText();
                }
            } else if (value.isObject()) {
                var fields = value.fields();
                while (fields.hasNext()) {
                    JsonNode item = fields.next().getValue();
                    if (item.isTextual()) {
                        return item.asText();
                    }
                }
            }
        }
        return null;
    }

    private static String textual(JsonNode json, String field) {
        JsonNode value = json.get(field);
        return value != null && value.isTextual() ? value.asText() : "";
    }

    private static Long since(Long at, long now) {
        if (at == null) {
            return null;
        }
        long delta = now - at;
        if (delta < 0) {
            delta = 0;
        }
        return delta / 1_000_000L;
    }

    private static Long until(Long at, long now) {
        if (at == null) {
            return null;
        }
        long delta = at - now;
        if (delta < 0) {
            delta = 0;
        }
        return delta / 1_000_000L;
    }

    private static final class Timing {
        Long started;
        Long lastChange;
        Long lastPull;
        Long nextPull;
        Long lastHeartbeat;
        Long nextHeartbeat;
        Long lastEvent;
    }

    private static final class Wake {
        boolean pull;
        boolean stop;
    }

    private static final class CachedPermit {
        final long at;
        final Decision decision;

        CachedPermit(long at, Decision decision) {
            this.at = at;
            this.decision = decision;
        }
    }

    private static final class Counters {
        final AtomicLong decisions = new AtomicLong();
        final AtomicLong allowed = new AtomicLong();
        final AtomicLong refused = new AtomicLong();
        final AtomicLong unavailable = new AtomicLong();
        final AtomicLong undischargeable = new AtomicLong();
        final AtomicLong pulls = new AtomicLong();
        final AtomicLong pullsChanged = new AtomicLong();
        final AtomicLong pullFailures = new AtomicLong();
        final AtomicLong heartbeats = new AtomicLong();
        final AtomicLong heartbeatFailures = new AtomicLong();
        final AtomicLong registrations = new AtomicLong();
        final AtomicLong eventsReceived = new AtomicLong();
        final AtomicLong eventsIgnored = new AtomicLong();
        final AtomicLong permitCacheHits = new AtomicLong();
        final AtomicLong decisionMicrosTotal = new AtomicLong();
        final AtomicLong decisionMicrosMax = new AtomicLong();
    }
}
