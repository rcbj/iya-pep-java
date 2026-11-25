// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.support;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * A stub PDP: the token endpoint, the control plane, the PIP, AuthZEN
 * evaluation and the decision-record door, on a real socket.
 */
public final class Stub implements AutoCloseable {
    public static final String REALM = "r1";
    public static final String NAME = "pep-orders";
    /** The DN the stub's registration answer names as the PEP's entry. */
    public static final String IDENTITY = "cn=pep-orders,ou=users,dc=example,dc=com";
    public static final String APP = "orders";

    public final String base;
    public final Script script = new Script();
    private final List<Seen> seen = new ArrayList<>();
    private final HttpServer server;
    private final ExecutorService executor;
    private int tokens;
    private boolean nonceAsked;

    private Stub(String base, HttpServer server, ExecutorService executor) {
        this.base = base;
        this.server = server;
        this.executor = executor;
    }

    public static Stub start() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            ExecutorService executor = Executors.newSingleThreadExecutor(runnable -> {
                Thread thread = new Thread(runnable, "iya-pep-stub");
                thread.setDaemon(true);
                return thread;
            });
            server.setExecutor(executor);
            int port = server.getAddress().getPort();
            Stub stub = new Stub("http://127.0.0.1:" + port + "/realm/" + REALM, server, executor);
            server.createContext("/", stub::handle);
            server.start();
            return stub;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public List<Seen> seen(String pathEnds) {
        synchronized (seen) {
            List<Seen> found = new ArrayList<>();
            for (Seen one : seen) {
                if (one.path.endsWith(pathEnds)) {
                    found.add(one);
                }
            }
            return found;
        }
    }

    public int count(String pathEnds) {
        return seen(pathEnds).size();
    }

    /** Waits up to {@code limit} for {@code condition} to hold. */
    public boolean waitUntil(Duration limit, java.util.function.Predicate<Stub> condition) {
        long until = System.nanoTime() + limit.toNanos();
        while (System.nanoTime() < until) {
            if (condition.test(this)) {
                return true;
            }
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        return condition.test(this);
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }

    private void handle(HttpExchange exchange) {
        try {
            String length = exchange.getRequestHeaders().getFirst("Content-Length");
            byte[] buf = new byte[0];
            if (length != null && !length.isEmpty() && !"0".equals(length)) {
                int n = Integer.parseInt(length);
                buf = exchange.getRequestBody().readNBytes(n);
            }
            String uriPath = exchange.getRequestURI().getPath();
            String query = exchange.getRequestURI().getRawQuery();
            List<String[]> headers = new ArrayList<>();
            exchange.getRequestHeaders().forEach((name, values) -> {
                for (String value : values) {
                    headers.add(new String[] {name, value});
                }
            });
            Seen one = new Seen(exchange.getRequestMethod(), uriPath == null ? "" : uriPath, query, headers,
                    new String(buf, StandardCharsets.UTF_8));
            synchronized (seen) {
                seen.add(one);
            }
            Script.Reply reply;
            synchronized (script) {
                int[] granted = new int[] {tokens};
                boolean[] asked = new boolean[] {nonceAsked};
                reply = script.answer(base, one, granted, asked);
                tokens = granted[0];
                nonceAsked = asked[0];
            }
            byte[] out = reply.body.getBytes(StandardCharsets.UTF_8);
            for (String[] header : reply.headers) {
                exchange.getResponseHeaders().add(header[0], header[1]);
            }
            exchange.sendResponseHeaders(reply.status, out.length);
            try (OutputStream stream = exchange.getResponseBody()) {
                stream.write(out);
            }
        } catch (Exception e) {
            try {
                exchange.sendResponseHeaders(500, -1);
            } catch (Exception ignored) {
                // The exchange is already gone.
            }
        } finally {
            exchange.close();
        }
    }

}
