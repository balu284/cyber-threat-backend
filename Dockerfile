# Build stage
FROM maven:3.8-openjdk-17-slim AS builder

WORKDIR /app

# Copy all files
COPY . .

# Build the application
RUN mvn clean package -DskipTests

# Run stage
FROM eclipse-temurin:17-jdk-jammy

WORKDIR /app

# Copy the jar from builder
COPY --from=builder /app/target/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
