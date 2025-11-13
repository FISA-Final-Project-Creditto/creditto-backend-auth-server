FROM amd64/amazoncorretto:17

WORKDIR /app

COPY ./build/libs/*.jar app.jar

EXPOSE 9000

ENTRYPOINT ["java", "-jar", "app.jar"]