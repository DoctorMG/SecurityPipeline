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
      stage('Vulnerabilites-Trivy') {
        steps {
          // bat('trivy fs . --format template --template "@D:\\Dev\\trivy\\contrib\\html.tpl" --output ".\\reports\\trivy-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"')

          powershell '''
            # Ordner erstellen, falls nicht vorhanden
            if (!(Test-Path ".\\reports")) {
                New-Item -ItemType Directory -Path ".\\reports"
            }

            # Zeitstempel erzeugen
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $outputFile = ".\\reports\\trivy-report-$timestamp.html"

            # Trivy-Scan mit HTML-Report ausführen
            Write-Host "Starte Trivy-Scan..."
            trivy fs . --format template --template "@D:\\Dev\\trivy\\contrib\\html.tpl" --output $outputFile

            # Trivy-Scan mit Log-Output ausführen
            Write-Host "Erzeuge Log"
            trivy fs . --format table
            
            # JSON-Ausgabe abrufen
            $json = trivy fs . --format json | ConvertFrom-Json

            # Kompakte Zusammenfassung erstellen
            $vulns = $json.Results.Vulnerabilities
            if ($vulns) {
                $total = $vulns.Count
                $critical = ($vulns | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
                $high = ($vulns | Where-Object { $_.Severity -eq 'HIGH' }).Count
                $medium = ($vulns | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
                $low = ($vulns | Where-Object { $_.Severity -eq 'LOW' }).Count

                Write-Host "=== Trivy Zusammenfassung ==="
                Write-Host "Gesamt: $total | CRITICAL: $critical | HIGH: $high | MEDIUM: $medium | LOW: $low"
            }
          '''
        }
      }    
      stage('Licenses-Trivy') {
        steps {
          powershell '''
            # Ordner erstellen, falls nicht vorhanden
            if (!(Test-Path ".\\reports")) {
                New-Item -ItemType Directory -Path ".\\reports"
            }

            # Zeitstempel erzeugen
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $outputFile = ".\\reports\\license-report-$timestamp.html"

            # Trivy-Scan mit HTML-Report ausführen
            Write-Host "Starte Trivy-Scan..."
            trivy fs . --scanners license --format template --template "@D:\\Dev\\trivy\\contrib\\html.tpl" --output $outputFile

            # Trivy-Scan mit Log-Output ausführen
            Write-Host "Erzeuge Log"
            trivy fs . --scanners license --format table
            
            # JSON-Ausgabe abrufen
            $json = trivy fs . --scanners license --format json | ConvertFrom-Json

            # Kompakte Zusammenfassung erstellen
            $vulns = $json.Results.Vulnerabilities
            if ($vulns) {
                $total = $vulns.Count
                $critical = ($vulns | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
                $high = ($vulns | Where-Object { $_.Severity -eq 'HIGH' }).Count
                $medium = ($vulns | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
                $low = ($vulns | Where-Object { $_.Severity -eq 'LOW' }).Count

                Write-Host "=== Trivy Zusammenfassung ==="
                Write-Host "Gesamt: $total | CRITICAL: $critical | HIGH: $high | MEDIUM: $medium | LOW: $low"
            }
          '''
        }
      }    
      stage('IaCScan-Checkov') {
        steps {
          bat("checkov -s -f main.tf")
        }
      }    
      stage('SBOM-CycloneDX-Trivy') {
        steps {
          powershell '''
            # Ordner erstellen, falls nicht vorhanden
            if (!(Test-Path ".\\sbom")) {
                New-Item -ItemType Directory -Path ".\\sbom"
            }

            # Zeitstempel erzeugen
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $outputFile = ".\\sbom\\cycloneBOM-$timestamp.json"

            # Trivy-Scan mit HTML-Report ausführen
            Write-Host "Generiere CycloneDX Report mit Scan ..."
            trivy fs . --format cyclonedx  --output $outputFile
          '''
        }
      }
      stage('SBOM-CycloneDX-BOV-Trivy') {
        steps {
          powershell '''
            # Ordner erstellen, falls nicht vorhanden
            if (!(Test-Path ".\\sbom")) {
                New-Item -ItemType Directory -Path ".\\sbom"
            }

            # Zeitstempel erzeugen
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $outputFile = ".\\sbom\\cycloneBOM-BOV-$timestamp.json"

            # Trivy-Scan mit HTML-Report ausführen
            Write-Host "Generiere CycloneDX Report mit Scan ..."
            trivy fs . --scanners vuln --format cyclonedx  --output $outputFile
          '''
        }
      }  
      stage('SBOM-SPDX-Trivy') {
        steps {
          powershell '''
            # Ordner erstellen, falls nicht vorhanden
            if (!(Test-Path ".\\sbom")) {
                New-Item -ItemType Directory -Path ".\\sbom"
            }

            # Zeitstempel erzeugen
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $outputFile = ".\\sbom\\SPDX-BOM-$timestamp.spdx"

            # Trivy-Scan mit HTML-Report ausführen
            Write-Host "Generiere SPDX Report mit Scan ..."
            trivy fs . --scanners vuln --format spdx  --output $outputFile
          '''
        }
      }
      stage('SBOM-JSON-Trivy') {
        steps {
          powershell '''
            # Ordner erstellen, falls nicht vorhanden
            if (!(Test-Path ".\\sbom")) {
                New-Item -ItemType Directory -Path ".\\sbom"
            }

            # Zeitstempel erzeugen
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $outputFile = ".\\sbom\\spdxBOM-$timestamp.json"

            # Trivy-Scan mit HTML-Report ausführen
            Write-Host "Generiere SPDX Report mit Scan ..."
            trivy fs . --scanners vuln --format spdx-json  --output $outputFile
          '''
        }
    }  
  }
}