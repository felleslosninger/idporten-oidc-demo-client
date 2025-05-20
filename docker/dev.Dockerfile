FROM maven:3.9-eclipse-temurin-24 as builder

ARG GIT_PACKAGE_TOKEN
ARG GIT_PACKAGE_USERNAME

ENV GIT_PACKAGE_TOKEN=${GIT_PACKAGE_TOKEN}
ENV GIT_PACKAGE_USERNAME=${GIT_PACKAGE_USERNAME}

COPY docker/settings.xml /root/.m2/settings.xml

WORKDIR /home/app
COPY pom.xml ./
COPY src ./src

RUN --mount=type=cache,target=/root/.m2/repository mvn -B package dependency:go-offline -Dmaven.test.skip=true -Dmaven.gitcommitid.skip=true


FROM eclipse-temurin:24-jre-noble

ARG APPLICATION=idporten-oidc-demo-client
RUN mkdir /var/log/${APPLICATION}
RUN mkdir /usr/local/webapps
WORKDIR /usr/local/webapps

COPY --from=builder /home/app/target/${APPLICATION}-DEV-SNAPSHOT.jar application.jar

ENV TZ=Europe/Oslo
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

EXPOSE 7074