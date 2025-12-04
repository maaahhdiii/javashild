# JavaShield Security Agent Dockerfile
# Multi-stage build for optimized image

# ==================== BUILD STAGE ====================
FROM eclipse-temurin:25-jdk AS builder

WORKDIR /app

# Copy Maven configuration
COPY pom.xml .
COPY mvnw .
COPY .mvn .mvn

# Download dependencies (cached layer)
RUN ./mvnw dependency:go-offline -B

# Copy source code
COPY src ./src

# Build the application
RUN ./mvnw package -DskipTests --enable-preview

# ==================== RUNTIME STAGE ====================
FROM eclipse-temurin:25-jre

LABEL maintainer="JavaShield Team"
LABEL description="AI-Powered Vulnerability Detection Agent"
LABEL version="1.0.0"

# Create non-root user for security
RUN groupadd -r javashield && useradd -r -g javashield javashield

WORKDIR /app

# Copy the built JAR
COPY --from=builder /app/target/vulnerability-detection-agent-1.0.0.jar app.jar

# Create directories for data persistence
RUN mkdir -p /app/data /app/logs /app/models && \
    chown -R javashield:javashield /app

# Switch to non-root user
USER javashield

# Environment variables
ENV JAVA_OPTS="--enable-preview -Xms512m -Xmx2048m"
ENV SERVER_PORT=8080
ENV SPRING_PROFILES_ACTIVE=production
ENV TZ=UTC

# Expose ports
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/actuator/health || exit 1

# Run the application
ENTRYPOINT ["sh", "-c", "java ${JAVA_OPTS} -jar app.jar"]
