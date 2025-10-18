FROM localhost:5005/jdk
EXPOSE 8080
COPY authorization-server.jar ./
RUN chmod 777 authorization-server.jar
CMD java -jar authorization-server.jar

