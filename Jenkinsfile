pipeline {
	agent any

	stages {
		stage('Build and Test') {
			steps {
				withCredentials([string(credentialsId: 'authserver_env', variable: 'ENV_CONTENT')]) {
					sh '''
                        echo "$ENV_CONTENT" > .env
                        chmod 600 .env
                        ls -al .env
                        echo "env 파일 적재 완료 ✔"
                    '''
				}

				sh 'chmod +x ./gradlew'
				sh './gradlew clean build'
			}
		}
	}

	post {
		always {
			junit 'build/test-results/test/*.xml'
		}
	}
}