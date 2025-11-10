pipeline {
	agent any

	environment {
		DOCKER_IMAGE = 'sw-team-5-auth-server'
		DOCKER_TAG = "${env.BUILD_NUMBER}"
		CONTAINER_NAME = 'sw_team_5_auth_server'
	}

	stages {
		stage('Build and Test') {
			steps {
				sh 'chmod +x ./gradlew'
				sh './gradlew processResources processTestResources'

				withCredentials(
					[
						string(credentialsId: 'authserver_env', variable: 'ENV_CONTENT'),
						string(credentialsId: 'jwt-private-pem', variable: 'PRIVATE_PEM_CONTENT'),
						string(credentialsId: 'jwt-public-pem', variable: 'PUBLIC_PEM_CONTENT')
					]
				) {
					sh '''
                        echo "$ENV_CONTENT" > .env
                        chmod 600 .env
                        ls -al .env
                        echo "env 파일 적재 완료 ✅"

                        echo "$ENV_CONTENT" > build/resources/test/application-test.properties

                        mkdir -p build/resources/main/keys
                        mkdir -p build/resources/test/keys

						echo "$PRIVATE_PEM_CONTENT" > build/resources/main/keys/jwt-private.pem
						echo "$PUBLIC_PEM_CONTENT" > build/resources/main/keys/jwt-public.pem
						chmod 600 build/resources/main/keys/jwt-private.pem

						echo "$PRIVATE_PEM_CONTENT" > build/resources/test/keys/jwt-private.pem
						echo "$PUBLIC_PEM_CONTENT" > build/resources/test/keys/jwt-public.pem
						chmod 600 build/resources/test/keys/jwt-private.pem

						echo ".pem 키 파일 생성 완료 ✅"
						ls -al build/resources/main/keys
						ls -al build/resources/test/keys
                    '''
				}

				sh './gradlew test'
				sh './gradlew bootJar'
			}
		}

		stage('Build Docker Image') {
			when {
				branch 'dev'
			}
			steps {
				script {
					sh '''
                        # Docker 이미지 빌드
                        docker build -t ${DOCKER_IMAGE}:${DOCKER_TAG} .
                        docker tag ${DOCKER_IMAGE}:${DOCKER_TAG} ${DOCKER_IMAGE}:dev-latest
                    '''
				}
			}
		}

		stage('Deploy to Dev') {
			when {
				branch 'dev'
			}
			steps {
				script {
					// 1. 호스트(Jenkins Agent)에 배포용 설정/키 파일 복사
					sh '''
                        mkdir -p /opt/creditto/config
                        cp .env /opt/creditto/config/.env
                        cp -r build/resources/main/keys /opt/creditto/config/
                    '''

					// 2. Docker 컨테이너 실행
					sh '''
                        # 기존 컨테이너 중지 및 제거
                        echo "기존 컨테이너 중지 및 제거 ❌"
                        docker stop ${CONTAINER_NAME} || true
                        docker rm ${CONTAINER_NAME} || true

                        # 새 컨테이너 실행 (호스트 볼륨 마운트)
                        echo "컨테이너 실행..✅"
                        docker run -d \
                            --name ${CONTAINER_NAME} \
                            -p 8490:8080 \
                            -v /opt/creditto/config/.env:/app/.env:ro \
                            -v /opt/creditto/config/keys:/app/keys:ro \
                            --network creditto-network \
                            --restart unless-stopped \
                            ${DOCKER_IMAGE}:dev-latest

                        sleep 15

                        echo "헬스 체크 시작...🔥"
                        curl -f http://localhost:8490/actuator/health || exit 1
                        echo "Deployment successful!"
                    '''
				}
			}
		}
	}

	post {
		always {
			junit testResults: 'build/test-results/test/*.xml', allowEmptyResults: true
		}
	}
}