// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.authzen;

/**
 * What the PEP knows about the call, written into the request as trusted
 * facts rather than read from the evaluation.
 */
public final class Trusted {
    /** The realm's id. Empty for the default realm. */
    public String realm = "";
    /**
     * The caller fact {@code urn:sts:xacml:authzen:caller}: the registration's
     * identity DN when the service named one, otherwise the PEP's name.
     */
    public String caller = "";
    /** The bound application. */
    public String application = "";
    /**
     * The bound application enforces fine-grained authorization. The request
     * then carries {@code urn:sts:xacml:fga:application} and
     * {@code urn:sts:xacml:fga:stage} = {@code access}, after every other attribute.
     */
    public boolean fga;

    public Trusted() {}

    public Trusted(String realm, String caller, String application, boolean fga) {
        this.realm = realm == null ? "" : realm;
        this.caller = caller == null ? "" : caller;
        this.application = application == null ? "" : application;
        this.fga = fga;
    }
}
