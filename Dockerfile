FROM amd64/amazoncorretto:17

WORKDIR /app

COPY ./build/libs/*.jar app.jar

ENV SPRING_PROFILES_ACTIVE=dev

EXPOSE 9000

ENTRYPOINT ["sh", "-c", "sleep 15 && java -jar app.jar"]