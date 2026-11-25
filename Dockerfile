# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
# `docker build --target test .` runs the suite. Do not run Maven on the host.
FROM maven:3.9-eclipse-temurin-26 AS test
WORKDIR /src
COPY . .
RUN mvn -B test
