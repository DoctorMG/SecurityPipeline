pipeline {
  agent any
  tools {
    maven 'Maven_3_8_7'
  }

  environment {
      JAVA_TOOL_OPTIONS = "-Dfile.encoding=UTF-8"
  }

  stages {
    stage('CompileandRunSonarAnalysis') {
      steps {
        withCredentials([string(credentialsId: 'SONAR_TOKEN', variable: 'SONAR_TOKEN')]) {
          bat("mvn -Dmaven.test.failure.ignore verify sonar:sonar -Dsonar.login=$SONAR_TOKEN -Dsonar.projectKey=easybuggy -Dsonar.host.url=http://localhost:9000/")
        }
      }
    }
    stage('BuildDockerImage') {
      steps {
        withDockerRegistry([credentialsId: "dockerlogin", url: ""]) {
          script {
            app = docker.build("dockington/checkcontainer")
          }
        }
      }
    }
    stage('ContainerScan-Snyk') {
      steps {
        withCredentials([string(credentialsId: 'SNYK_TOKEN', variable: 'SNYK_TOKEN')]) {
          script {
            try {
              bat("D:\\Dev\\snyk\\snyk-win.exe container test dockington/checkcontainer")
            } catch (err) {
              echo err.getMessage()
            }
          }
        }
      }
    }
    stage('SCA-Snyk') {
      steps {
        withCredentials([string(credentialsId: 'SNYK_TOKEN', variable: 'SNYK_TOKEN')]) {
          bat("mvn snyk:test -fn")
        }
      }
    }
    stage('DAST-ZAP') {
      steps {
        bat("D:\\Dev\\ZAP_2.16.0_Crossplatform\\ZAP_2.16.0\\zap.sh -port 9393 -cmd -quickurl https://www.example.com -quickprogress -quickout D:\\Dev\\ZAP_2.16.0_Crossplatform\\ZAP_2.16.0\\Output.html")
      }
    }
    stage('SecretsScan-Trivy') {
      steps {
        bat("trivy fs .")
      }
    }
    stage('IaCScan-Checkov') {
      steps {
        bat("checkov -s -f main.tf")
      }
    }

  }
}
