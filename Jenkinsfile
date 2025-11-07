pipeline {
	agent any

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
                        echo "env 파일 적재 완료 ✔"

                        echo "$ENV_CONTENT" > build/resources/test/application-test.properties

                        mkdir -p build/resources/main/keys
                        mkdir -p build/resources/test/keys

						echo "$PRIVATE_PEM_CONTENT" > build/resources/main/keys/jwt-private.pem
						echo "$PUBLIC_PEM_CONTENT" > build/resources/main/keys/jwt-public.pem
						chmod 600 build/resources/main/keys/jwt-private.pem

						echo "$PRIVATE_PEM_CONTENT" > build/resources/test/keys/jwt-private.pem
						echo "$PUBLIC_PEM_CONTENT" > build/resources/test/keys/jwt-public.pem
						chmod 600 build/resources/test/keys/jwt-private.pem

						echo ".pem 키 파일 생성 완료 ✔"
						ls -al build/resources/main/keys
						ls -al build/resources/test/keys
                    '''
				}

				sh './gradlew build'
			}
		}
	}

	post {
		always {
			junit testResults: 'build/test-results/test/*.xml', allowEmptyResults: true
		}
	}
}