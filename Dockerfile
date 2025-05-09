
# Use a multi-stage builder image
FROM maven:3.9-eclipse-temurin-24 AS build
COPY . /build
WORKDIR /build
# Build the app
# Artifact will be stored at /build/target/json-web-key-generator-0.9-SNAPSHOT-jar-with-dependencies.jar
RUN mvn package

# Build the runtime image
FROM gcr.io/distroless/java21-debian12
ARG GIT_COMMIT=unspecified
ARG GIT_TAG=unspecified
LABEL org.opencontainers.image.authors="Ross Cousens"
LABEL org.opencontainers.image.revision=$GIT_COMMIT
LABEL org.opencontainers.image.version="$GIT_TAG"
COPY --from=build /build/target/jwk-to-vault-0.9-SNAPSHOT-jar-with-dependencies.jar /app/jwk-to-vault.jar
WORKDIR /app
ENTRYPOINT ["java", "-jar", "jwk-to-vault.jar"]
