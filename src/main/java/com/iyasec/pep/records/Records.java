// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.records;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.iyasec.pep.Json;
import com.iyasec.pep.PepException;
import com.iyasec.pep.credential.Audience;
import com.iyasec.pep.credential.Credential;
import com.iyasec.pep.http.Answer;
import com.iyasec.pep.http.Body;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

/**
 * Decision records a local PEP pushes to {@code POST /admin-api/pep-audit}.
 * Delivery is at least once: a record leaves the queue only when the service
 * acknowledges its {@code seq}. The queue is bounded; the oldest record is
 * dropped when it is full.
 */
public final class Records {
    /** The most records a push carries. */
    public static final int BATCH = 500;
    /** The most records held while the service cannot be reached. */
    public static final int BUFFER = 10_000;

    private final String instance;
    private final Object lock = new Object();
    private final ArrayDeque<ObjectNode> queue = new ArrayDeque<>();
    private long seq;
    private long dropped;
    private long shipped;

    public Records(String instance) {
        this.instance = instance;
    }

    /** Queues one record. {@code seq} and {@code at} are added here. */
    public void push(ObjectNode record) {
        ObjectNode copy = record == null ? Json.object() : record.deepCopy();
        synchronized (lock) {
            seq++;
            copy.put("seq", seq);
            copy.put("at", nowRfc3339());
            if (queue.size() >= BUFFER) {
                queue.removeFirst();
                dropped++;
            }
            queue.addLast(copy);
        }
    }

    public int queued() {
        synchronized (lock) {
            return queue.size();
        }
    }

    /** Shipped, then dropped. */
    public long[] counts() {
        synchronized (lock) {
            return new long[] {shipped, dropped};
        }
    }

    /**
     * Pushes one batch. Records up to the acknowledged {@code seq} leave the queue.
     *
     * @return how many left the queue
     */
    public int ship(Credential credential, String url) throws PepException {
        List<ObjectNode> batch;
        synchronized (lock) {
            batch = new ArrayList<>();
            int n = Math.min(BATCH, queue.size());
            int i = 0;
            for (ObjectNode record : queue) {
                if (i++ >= n) {
                    break;
                }
                batch.add(record);
            }
        }
        if (batch.isEmpty()) {
            return 0;
        }
        ObjectNode body = Json.object();
        body.put("instance", instance);
        ArrayNode events = Json.array();
        for (ObjectNode record : batch) {
            events.add(record);
        }
        body.set("events", events);
        Answer answer = credential.call(Audience.AUDIT, "POST", url, "application/json", List.of(), Body.json(body));
        if (answer.status != 200) {
            String text = answer.body == null ? "" : answer.body;
            if (text.length() > 200) {
                text = text.substring(0, 200);
            }
            throw new PepException("refused", url + " answered " + answer.status + ": " + text);
        }
        JsonNode json = answer.json();
        long acknowledged = 0;
        if (json != null) {
            JsonNode ack = json.get("acknowledged");
            if (ack != null && ack.isIntegralNumber() && ack.canConvertToLong() && ack.longValue() >= 0) {
                acknowledged = ack.longValue();
            }
        }
        synchronized (lock) {
            int before = queue.size();
            while (!queue.isEmpty()) {
                JsonNode seqNode = queue.peekFirst().get("seq");
                if (seqNode == null || !seqNode.isIntegralNumber() || !seqNode.canConvertToLong()) {
                    break;
                }
                if (seqNode.longValue() > acknowledged) {
                    break;
                }
                queue.removeFirst();
            }
            int gone = before - queue.size();
            shipped += gone;
            return gone;
        }
    }

    /** Now, as RFC 3339 UTC with milliseconds. */
    public static String nowRfc3339() {
        long millis = System.currentTimeMillis();
        if (millis < 0) {
            millis = 0;
        }
        long secs = Math.floorDiv(millis, 1000);
        int fraction = (int) Math.floorMod(millis, 1000);
        long days = Math.floorDiv(secs, 86_400);
        long rem = Math.floorMod(secs, 86_400);
        long[] ymd = civilFromDays(days);
        return String.format("%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                ymd[0], ymd[1], ymd[2], rem / 3600, (rem % 3600) / 60, rem % 60, fraction);
    }

    /** Howard Hinnant's days-from-civil inverse. Year, month, day. */
    static long[] civilFromDays(long days) {
        long z = days + 719_468;
        long era = Math.floorDiv(z, 146_097);
        long doe = Math.floorMod(z, 146_097);
        long yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        long mp = (5 * doy + 2) / 153;
        long d = doy - (153 * mp + 2) / 5 + 1;
        long m = mp < 10 ? mp + 3 : mp - 9;
        long y = yoe + era * 400 + (m <= 2 ? 1 : 0);
        return new long[] {y, m, d};
    }
}
