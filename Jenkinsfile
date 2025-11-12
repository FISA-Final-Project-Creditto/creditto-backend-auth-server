pipeline {
	agent any

	stages {
		stage('Build and Test') {
			steps {
				sh 'chmod +x ./gradlew'
				sh './gradlew clean'
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

                        echo "$ENV_CONTENT" > build/resources/test/application-test.yml

                        mkdir -p build/resources/main/keys
                        mkdir -p build/resources/test/keys

						echo "$PRIVATE_PEM_CONTENT" > build/resources/main/keys/jwt-private.pem
						echo "$PUBLIC_PEM_CONTENT" > build/resources/main/keys/jwt-public.pem
						chmod 600 build/resources/main/keys/jwt-private.pem

						echo "$PRIVATE_PEM_CONTENT" > build/resources/test/keys/jwt-private.pem
						echo "$PUBLIC_PEM_CONTENT" > build/resources/test/keys/jwt-public.pem
						chmod 600 build/resources/test/keys/jwt-private.pem
                    '''
				}

				sh './gradlew build'
				sh 'rm .env'
			}
		}

		stage('SonarQube Analysis') {
			steps {
				withSonarQubeEnv('sonarqube') {
					sh """
						./gradlew sonar \
						  -Dsonar.projectKey=sw_team_5_auth_server \
						  -Dsonar.host.url=http://sw-team-5-sonarqube:9000 \
						  -Dsonar.login=$SONAR_AUTH_TOKEN
					"""
				}
			}
		}

		stage('Quality Gate') {
			steps {
				timeout(time: 3, unit: 'MINUTES') {
					waitForQualityGate abortPipeline: true
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