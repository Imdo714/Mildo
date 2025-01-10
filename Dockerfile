# Base image 설정
FROM openjdk:17-jdk-slim

# 애플리케이션 디렉토리 설정
WORKDIR /app

# JAR 파일 복사
COPY target/mildo-0.0.1-SNAPSHOT.jar /app/mildo-0.0.1-SNAPSHOT.jar

# 애플리케이션 실행
ENTRYPOINT ["java", "-jar", "mildo-0.0.1-SNAPSHOT.jar"]