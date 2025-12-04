// Jenkinsfile for JavaShield Security Agent
// Jenkins Pipeline for Continuous Integration and Security Analysis

pipeline {
    agent any
    
    tools {
        maven 'Maven-3.9'
        jdk 'JDK-25'
    }
    
    environment {
        MAVEN_OPTS = '-Xmx4096m'
        JAVA_HOME = tool 'JDK-25'
        PATH = "${JAVA_HOME}/bin:${env.PATH}"
        
        // Security scan configuration
        ZAP_HOME = '/opt/zaproxy'
        NVD_API_KEY = credentials('nvd-api-key')
        MISP_API_KEY = credentials('misp-api-key')
    }
    
    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timestamps()
        timeout(time: 1, unit: 'HOURS')
        disableConcurrentBuilds()
    }
    
    triggers {
        // Build on push
        pollSCM('H/5 * * * *')
        // Nightly security scan
        cron('0 0 * * *')
    }
    
    stages {
        // ==================== CHECKOUT ====================
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    env.GIT_COMMIT_SHORT = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
                    env.GIT_BRANCH_NAME = sh(script: 'git rev-parse --abbrev-ref HEAD', returnStdout: true).trim()
                }
                echo "Building commit ${env.GIT_COMMIT_SHORT} on branch ${env.GIT_BRANCH_NAME}"
            }
        }
        
        // ==================== BUILD ====================
        stage('Build') {
            steps {
                sh 'mvn clean compile -DskipTests'
            }
            post {
                success {
                    echo 'Build completed successfully'
                }
                failure {
                    echo 'Build failed'
                }
            }
        }
        
        // ==================== TEST ====================
        stage('Unit Tests') {
            steps {
                sh 'mvn test'
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'target/surefire-reports/*.xml'
                }
            }
        }
        
        // ==================== STATIC ANALYSIS ====================
        stage('Static Analysis') {
            parallel {
                stage('SpotBugs') {
                    steps {
                        sh 'mvn spotbugs:spotbugs -DskipTests || true'
                    }
                    post {
                        always {
                            recordIssues(
                                enabledForFailure: true,
                                tools: [spotBugs(pattern: 'target/spotbugsXml.xml')]
                            )
                        }
                    }
                }
                
                stage('PMD') {
                    steps {
                        sh 'mvn pmd:pmd -DskipTests || true'
                    }
                    post {
                        always {
                            recordIssues(
                                enabledForFailure: true,
                                tools: [pmdParser(pattern: 'target/pmd.xml')]
                            )
                        }
                    }
                }
                
                stage('CheckStyle') {
                    steps {
                        sh 'mvn checkstyle:checkstyle -DskipTests || true'
                    }
                    post {
                        always {
                            recordIssues(
                                enabledForFailure: true,
                                tools: [checkStyle(pattern: 'target/checkstyle-result.xml')]
                            )
                        }
                    }
                }
            }
        }
        
        // ==================== DEPENDENCY CHECK ====================
        stage('OWASP Dependency Check') {
            steps {
                dependencyCheck additionalArguments: '''
                    --scan .
                    --format HTML
                    --format XML
                    --format JSON
                    --failOnCVSS 7
                    --enableRetired
                    --nvdApiKey ${NVD_API_KEY}
                ''', odcInstallation: 'OWASP-DC'
            }
            post {
                always {
                    dependencyCheckPublisher pattern: 'dependency-check-report.xml'
                    archiveArtifacts artifacts: 'dependency-check-report.*', fingerprint: true
                }
            }
        }
        
        // ==================== PACKAGE ====================
        stage('Package') {
            steps {
                sh 'mvn package -DskipTests'
            }
            post {
                success {
                    archiveArtifacts artifacts: 'target/*.jar', fingerprint: true
                }
            }
        }
        
        // ==================== DYNAMIC ANALYSIS ====================
        stage('Dynamic Security Scan') {
            when {
                anyOf {
                    branch 'main'
                    branch 'develop'
                    triggeredBy 'TimerTrigger'
                }
            }
            steps {
                script {
                    // Start application in background
                    sh '''
                        java --enable-preview -jar target/vulnerability-detection-agent-1.0.0.jar &
                        sleep 30
                    '''
                    
                    // Run OWASP ZAP scan
                    sh '''
                        ${ZAP_HOME}/zap.sh -daemon -host 127.0.0.1 -port 8090 \
                            -config api.key=jenkins-zap-key &
                        sleep 10
                        
                        # Run baseline scan
                        ${ZAP_HOME}/zap-baseline.py \
                            -t http://localhost:8080 \
                            -r zap-report.html \
                            -x zap-report.xml \
                            -J zap-report.json \
                            || true
                        
                        # Stop ZAP
                        curl "http://127.0.0.1:8090/JSON/core/action/shutdown/?apikey=jenkins-zap-key" || true
                    '''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'zap-report.*', fingerprint: true, allowEmptyArchive: true
                    publishHTML(target: [
                        allowMissing: true,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: '.',
                        reportFiles: 'zap-report.html',
                        reportName: 'OWASP ZAP Report'
                    ])
                }
            }
        }
        
        // ==================== THREAT INTELLIGENCE ====================
        stage('Threat Intelligence Check') {
            when {
                anyOf {
                    branch 'main'
                    triggeredBy 'TimerTrigger'
                }
            }
            steps {
                script {
                    // Check dependencies against threat intelligence feeds
                    sh '''
                        # Extract dependency list
                        mvn dependency:list -DoutputFile=dependencies.txt
                        
                        # Run threat intelligence check (using the built-in NVD client)
                        java --enable-preview -cp target/vulnerability-detection-agent-1.0.0.jar \
                            com.security.ai.tools.ThreatIntelligenceChecker dependencies.txt || true
                    '''
                }
            }
        }
        
        // ==================== DOCKER BUILD ====================
        stage('Docker Build') {
            when {
                branch 'main'
            }
            steps {
                script {
                    docker.build("javashield:${env.GIT_COMMIT_SHORT}")
                }
            }
        }
        
        // ==================== DOCKER PUSH ====================
        stage('Docker Push') {
            when {
                branch 'main'
            }
            steps {
                script {
                    docker.withRegistry('https://registry.hub.docker.com', 'docker-hub-credentials') {
                        docker.image("javashield:${env.GIT_COMMIT_SHORT}").push()
                        docker.image("javashield:${env.GIT_COMMIT_SHORT}").push('latest')
                    }
                }
            }
        }
        
        // ==================== DEPLOY TO STAGING ====================
        stage('Deploy to Staging') {
            when {
                branch 'develop'
            }
            steps {
                echo 'Deploying to staging environment...'
                // Add deployment steps here
            }
        }
        
        // ==================== DEPLOY TO PRODUCTION ====================
        stage('Deploy to Production') {
            when {
                branch 'main'
            }
            input {
                message 'Deploy to production?'
                ok 'Deploy'
            }
            steps {
                echo 'Deploying to production environment...'
                // Add deployment steps here
            }
        }
    }
    
    post {
        always {
            // Cleanup
            cleanWs()
        }
        success {
            echo 'Pipeline completed successfully!'
            // Send success notification
            script {
                if (env.BRANCH_NAME == 'main') {
                    // emailext (
                    //     subject: "SUCCESS: Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]'",
                    //     body: "Build succeeded: ${env.BUILD_URL}",
                    //     recipientProviders: [[$class: 'DevelopersRecipientProvider']]
                    // )
                }
            }
        }
        failure {
            echo 'Pipeline failed!'
            // Send failure notification
            script {
                // emailext (
                //     subject: "FAILURE: Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]'",
                //     body: "Build failed: ${env.BUILD_URL}",
                //     recipientProviders: [[$class: 'DevelopersRecipientProvider']]
                // )
            }
        }
        unstable {
            echo 'Pipeline is unstable (tests or analysis failed)'
        }
    }
}
