FROM maven:3.8-eclipse-temurin-17 as builder

ARG GIT_PACKAGE_TOKEN
ARG GIT_PACKAGE_USERNAME

ENV GIT_PACKAGE_TOKEN=${GIT_PACKAGE_TOKEN}
ENV GIT_PACKAGE_USERNAME=${GIT_PACKAGE_USERNAME}

COPY pom.xml /home/app/
COPY docker/settings.xml /root/.m2/settings.xml
RUN mvn -f /home/app/pom.xml dependency:copy-dependencies

COPY src /home/app/src
RUN mvn -f /home/app/pom.xml clean package -Dmaven.test.skip=true -Dmaven.gitcommitid.skip=true


FROM eclipse-temurin:17-jre-jammy

ARG APPLICATION=altinn-gateway
RUN mkdir /var/log/${APPLICATION}

COPY --from=builder /home/app/target/altinn-gateway.jar /usr/local/webapps/application.jar
COPY docker/application-dev.yaml /usr/local/webapps/
COPY src/main/resources/altinn*.jks /usr/local/webapps/

ENV TZ=Europe/Oslo
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

EXPOSE 7085