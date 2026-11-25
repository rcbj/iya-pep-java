// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep;

/**
 * Whether the host's signal stream can carry {@code pep-policies-changed}.
 * Reported on the heartbeat so the console shows a local PEP that would
 * never hear of a change.
 */
public enum EventStream {
    /** The host has no signal stream ({@code signals: false}); the PEP polls. */
    NONE,
    /** The stream is running and asked for the event type. */
    REQUESTED,
    /** The stream's configuration excludes the event type. */
    EXCLUDED,
    /** The stream is not running or not healthy. */
    DOWN;

    public String asString() {
        return switch (this) {
            case NONE -> "none";
            case REQUESTED -> "requested";
            case EXCLUDED -> "excluded";
            case DOWN -> "down";
        };
    }
}
