FROM localhost:5005/jdk
ENV DOCKER_COMPOSE_ENABLED=false
ENV DOCKER_COMPOSE_FILE=/docker-compose.yml
EXPOSE 8080
COPY authorization-server.jar ./
COPy authorization-server/docker-compose.yml .
RUN chmod 777 authorization-server.jar
CMD java -jar authorization-server.jar
