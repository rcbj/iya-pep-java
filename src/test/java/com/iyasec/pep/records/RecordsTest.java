// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.records;

import com.iyasec.pep.Json;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RecordsTest {
    @Test
    void daysBecomeDates() {
        assertArrayEquals(new long[] {1970, 1, 1}, Records.civilFromDays(0));
        assertArrayEquals(new long[] {2026, 1, 1}, Records.civilFromDays(20_454));
        assertArrayEquals(new long[] {2000, 2, 29}, Records.civilFromDays(11_016));
        assertTrue(Records.nowRfc3339().endsWith("Z"));
    }

    @Test
    void aFullQueueDropsTheOldest() {
        Records records = new Records("i");
        for (int i = 0; i < Records.BUFFER + 3; i++) {
            records.push(Json.object().put("kind", "authzen"));
        }
        assertEquals(Records.BUFFER, records.queued());
        assertEquals(3L, records.counts()[1]);
    }
}
