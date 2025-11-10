FROM amd64/amazoncorretto:17

WORKDIR /app

COPY ./build/libs/*.jar app.jar

ENV SPRING_PROFILES_ACTIVE=dev

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]