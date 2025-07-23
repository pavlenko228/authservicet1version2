FROM openjdk:17-jdk-slim

WORKDIR /app

COPY target/authservice.jar authservice.jar

EXPOSE 8444

ENTRYPOINT ["java", "-jar", "authservice.jar"]