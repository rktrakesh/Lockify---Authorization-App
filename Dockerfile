# --- STAGE 1: Build Stage ---
FROM maven:3.8.5-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src ./src
RUN mvn clean package -DskipTests




# --- STAGE 2: Run Stage ---
FROM eclipse-temurin:17-jre-alpine

# Alpine-specific commands for creating a non-root user
RUN addgroup -S spring && adduser -S spring -G spring
USER spring

WORKDIR /app
COPY --from=build /app/target/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]