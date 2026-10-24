/*
========================================================
 QUANTUM SHIELD - LANGUAGE SWITCHER
========================================================
 Languages:
   en = English
   es = Spanish
   fr = French
   de = German

 Features:
 1. Translates website text and input hints.
 2. Supports dynamically added text.
 3. Remembers the selected language.
 4. Allows switching back to English.
 5. Does not change the website layout or CSS.
========================================================
*/

// ------------------------------------------------------
// 1. TRANSLATION DICTIONARY
// ------------------------------------------------------

const translations = {
    en: {},

    es: {
        "Dashboard Home": "Inicio del panel",
        "Threat Intelligence": "Inteligencia de amenazas",
        "Threat Intelligence (AI)": "Inteligencia de amenazas (IA)",
        "Network Reconnaissance": "Reconocimiento de red",
        "Vulnerability Analysis": "Análisis de vulnerabilidades",
        "Infrastructure Monitoring": "Supervisión de infraestructura",
        "Threat Dashboard": "Panel de amenazas",
        "Scan History": "Historial de análisis",
        "AI Security Assistant": "Asistente de seguridad de IA",
        "Scan Configuration": "Configuración del análisis",
        "System Settings": "Configuración del sistema",
        "Settings": "Configuración",
        "Logout": "Cerrar sesión",
        "Dashboard": "Panel de control",
        "Security Dashboard": "Panel de seguridad",
        "Quantum Shield AI Security Operations Center": "Centro de operaciones de seguridad de IA de Quantum Shield",
        "AI-Powered Enterprise Vulnerability Intelligence Platform for advanced infrastructure reconnaissance, threat analysis, and cybersecurity operations.": "Plataforma empresarial de inteligencia de vulnerabilidades basada en IA para el reconocimiento de infraestructura, el análisis de amenazas y las operaciones de ciberseguridad.",
        "Customize platform scanner presets, export templates, and security behavior.": "Personaliza los perfiles del escáner, las plantillas de exportación y las opciones de seguridad.",
        "Quick Scan": "Análisis rápido",
        "Launch Scan": "Iniciar análisis",
        "Start Scan": "Iniciar análisis",
        "Scan Results": "Resultados del análisis",
        "Download PDF Report": "Descargar informe PDF",
        "Reset Defaults": "Restablecer valores",
        "Save Global Settings": "Guardar configuración global",
        "Back to Dashboard Home": "Volver al panel principal",
        "Scanner Configuration": "Configuración del escáner",
        "Default Scan Preset": "Perfil de análisis predeterminado",
        "Preset scan mode chosen upon startup.": "Modo de análisis seleccionado al iniciar.",
        "Scan Timeout Limit": "Límite de tiempo del análisis",
        "Max waiting duration per network task.": "Tiempo máximo de espera por tarea de red.",
        "Aggressiveness Level": "Nivel de agresividad",
        "Timing template (-T setting).": "Configuración de temporización (-T).",
        "Report & Export Formatting": "Formato de informes y exportación",
        "Enforced Export Format": "Formato de exportación obligatorio",
        "Primary file type format for downloaded reports.": "Formato principal de los informes descargados.",
        "Include AI Summary Matrix": "Incluir resumen de IA",
        "Append AI-driven security tips to reports.": "Añadir consejos de seguridad generados por IA a los informes.",
        "Include Raw Terminal Logs": "Incluir registros de terminal",
        "Attach command line output in report appendix.": "Adjuntar la salida de la línea de comandos al informe.",
        "Security & Interface Options": "Opciones de seguridad e interfaz",
        "Display Language": "Idioma de visualización",
        "Select the user interface display language.": "Selecciona el idioma de la interfaz.",
        "Interface Theme Color": "Color del tema de la interfaz",
        "Accent layout style for your panels.": "Estilo de color para los paneles.",
        "Strict Target Input Sanitization": "Validación estricta del objetivo",
        "Block invalid IP or domain structures automatically.": "Bloquear automáticamente direcciones IP o dominios no válidos.",
        "Settings saved successfully!": "¡Configuración guardada correctamente!",
        "Success Alert Popup": "Ventana emergente de éxito",
        "English": "Inglés",
        "Español (Spanish)": "Español",
        "Français (French)": "Francés",
        "Deutsch (German)": "Alemán",
        "TCP SYN / Stealth Scan": "Análisis TCP SYN / sigiloso",
        "TCP Connect Scan": "Análisis de conexión TCP",
        "TCP ACK Scan": "Análisis TCP ACK",
        "TCP Window Scan": "Análisis de ventana TCP",
        "TCP Maimon Scan": "Análisis TCP Maimon",
        "TCP FIN Scan": "Análisis TCP FIN",
        "TCP NULL Scan": "Análisis TCP NULL",
        "TCP Xmas Scan": "Análisis TCP Xmas",
        "UDP Scan": "Análisis UDP",
        "IP Protocol Scan": "Análisis de protocolo IP",
        "Custom TCP Flag Scan": "Análisis con indicadores TCP personalizados",
        "Idle Scan": "Análisis inactivo",
        "FTP Bounce Scan": "Análisis FTP Bounce",
        "OS Detection": "Detección del sistema operativo",
        "Intense Scan": "Análisis intensivo",
        "All TCP Ports Scan": "Análisis de todos los puertos TCP",
        "Ping / Host Discovery": "Ping / detección de host",
        "Vulnerability Scan": "Análisis de vulnerabilidades",
        "Service Version Detection (-sV --version-intensity 5)": "Detección de versiones de servicios (-sV --version-intensity 5)",
        "Default Web Script Scan (-sV -sC)": "Análisis web con scripts predeterminados (-sV -sC)",
        "Vulnerability Detection Script (--script vuln)": "Script de detección de vulnerabilidades (--script vuln)",
        "Web Directory Brute-Forcing (--script http-enum)": "Fuerza bruta de directorios web (--script http-enum)",
        "SSL/TLS Security Auditing (--script ssl-enum-ciphers)": "Auditoría de seguridad SSL/TLS (--script ssl-enum-ciphers)",
        "Comprehensive Web Auditing (--script \"http-*\")": "Auditoría web completa (--script \"http-*\")",
        "Nikto Web Scan": "Análisis web con Nikto",
        "SQLMap Detection Scan": "Análisis de detección SQLMap",
        "Custom TCP Flags": "Indicadores TCP personalizados",
        "Zombie Host": "Host zombi",
        "FTP Bounce Relay": "Retransmisión FTP Bounce",
        "When to Use:": "Cuándo utilizarlo:",
        "Pros:": "Ventajas:",
        "Cons:": "Desventajas:",
        "Very fast and efficient.": "Muy rápido y eficiente.",
        "Launch Scan": "Iniciar análisis",
        "Network Recon": "Reconocimiento de red",
        "Threat Analysis": "Análisis de amenazas",
        "Infrastructure Monitoring": "Supervisión de infraestructura",
        "Threat Engine Online": "Motor de amenazas en línea",
        "AI Monitoring Active": "Supervisión de IA activa",
        "SOC Infrastructure Stable": "Infraestructura SOC estable",
        "QUANTUM SOC INTELLIGENCE CORE": "NÚCLEO DE INTELIGENCIA SOC DE QUANTUM",
        "System online. I am optimized for digital forensics metrics, architecture design documentation validation, and live network scan analysis. Ask me anything.": "Sistema en línea. Estoy optimizado para métricas forenses digitales, validación de documentación de arquitectura y análisis de escaneos de red en tiempo real. Pregúntame lo que quieras.",
        "EXECUTE": "EJECUTAR",
        "AI CHAT": "CHAT DE IA",
        "Initializing Threat Intelligence Engine...": "Inicializando el motor de inteligencia de amenazas...",
        "Target:": "Objetivo:",
        "Download PDF Report": "Descargar informe PDF",
        "HOST STATUS": "ESTADO DEL HOST",
        "OS DETECTION": "DETECCIÓN DEL SISTEMA OPERATIVO",
        "SERVICES DETECTED": "SERVICIOS DETECTADOS",
        "VULNERABILITY FINDINGS": "VULNERABILIDADES DETECTADAS",
        "PROTOCOLS DETECTED": "PROTOCOLOS DETECTADOS",
        "WEB FINDINGS": "HALLAZGOS WEB",
        "OPEN PORTS": "PUERTOS ABIERTOS",
        "THREAT SCORE": "PUNTUACIÓN DE AMENAZA",
        "THREAT LEVEL": "NIVEL DE AMENAZA",
        "SCAN STATUS": "ESTADO DEL ANÁLISIS",
        "COMPLETE": "COMPLETADO",
        "Threat Distribution": "Distribución de amenazas",
        "NO THREAT FINDINGS": "NO SE DETECTARON AMENAZAS",
        "This scan returned no risk-rated findings.": "Este análisis no devolvió hallazgos con clasificación de riesgo.",
        "Scan Timeline": "Cronología del análisis",
        "Target Connection Completed": "Conexión con el objetivo completada",
        "Web Server Analysis Completed": "Análisis del servidor web completado",
        "Web Security Checks Completed": "Comprobaciones de seguridad web completadas",
        "CVE Intelligence Feed": "Fuente de inteligencia CVE",
        "Reference reported by the selected security scan": "Referencia proporcionada por el análisis de seguridad seleccionado",
        "SCAN REF": "REFERENCIA DEL ANÁLISIS",
        "No CVE references were reported by this scan.": "Este análisis no proporcionó referencias CVE.",
        "Web Security Recommendations": "Recomendaciones de seguridad web",
        "AI Security Recommendations": "Recomendaciones de seguridad de IA",
        "Disable unused exposed services": "Desactivar servicios expuestos que no se utilicen",
        "Harden SSH configuration policies": "Reforzar la configuración de SSH",
        "Upgrade outdated services": "Actualizar los servicios obsoletos",
        "Enable WAF and firewall filtering": "Activar el filtrado WAF y del cortafuegos",
        "Schedule recurring vulnerability assessments": "Programar evaluaciones periódicas de vulnerabilidades",
        "SCAN INTELLIGENCE": "INTELIGENCIA DEL ANÁLISIS",
        "Current Scan": "Análisis actual",
        "Only results from the scan you performed are displayed.": "Solo se muestran los resultados del análisis que realizaste.",
        "QUICK SCAN": "ANÁLISIS RÁPIDO",
        "Network Exposure": "Exposición de red",
        "SERVICES": "SERVICIOS",
        "TARGET": "OBJETIVO",
        "PORT": "PUERTO",
        "STATE": "ESTADO",
        "SERVICE": "SERVICIO",
        "No open ports detected.": "No se detectaron puertos abiertos.",
        "VERSION DETECTION": "DETECCIÓN DE VERSIONES",
        "Service Intelligence": "Inteligencia de servicios",
        "VERSIONS FOUND": "VERSIONES ENCONTRADAS",
        "No service/version information detected.": "No se detectó información de servicios o versiones.",
        "Target Fingerprint": "Huella del objetivo",
        "DETECTED OS": "SISTEMA OPERATIVO DETECTADO",
        "DEVICE TYPE": "TIPO DE DISPOSITIVO",
        "CONFIDENCE": "CONFIANZA",
        "OS ANALYSIS": "ANÁLISIS DEL SISTEMA OPERATIVO",
        "Not detected": "No detectado",
        "Unknown": "Desconocido",
        "No operating-system information was returned.": "No se devolvió información del sistema operativo.",
        "VULNERABILITY SCAN": "ANÁLISIS DE VULNERABILIDADES",
        "Threat Assessment": "Evaluación de amenazas",
        "HIGH": "ALTO",
        "MEDIUM": "MEDIO",
        "LOW": "BAJO",
        "CVE REFERENCES FROM THIS SCAN": "REFERENCIAS CVE DE ESTE ANÁLISIS",
        "RISK": "RIESGO",
        "SCAN DESCRIPTION": "DESCRIPCIÓN DEL ANÁLISIS",
        "TARGET WEB SERVER": "SERVIDOR WEB OBJETIVO",
        "CVE REFERENCES REPORTED BY NIKTO": "REFERENCIAS CVE PROPORCIONADAS POR NIKTO",
        "CVE REFERENCES": "REFERENCIAS CVE",
        "No CVE references were reported in the Nikto output.": "La salida de Nikto no contiene referencias CVE.",
        "FINDING": "HALLAZGO",
        "No Nikto findings were returned for this target.": "Nikto no encontró problemas para este objetivo.",
        "SQL Injection Assessment": "Evaluación de inyección SQL",
        "Deep SQL Injection Assessment": "Evaluación profunda de inyección SQL",
        "Database Fingerprint": "Huella de la base de datos",
        "Database Enumeration": "Enumeración de bases de datos",
        "RISK LEVEL": "NIVEL DE RIESGO",
        "SCAN MODE": "MODO DE ANÁLISIS",
        "SQLMAP TARGET URL": "URL OBJETIVO DE SQLMAP",
        "SQLMAP ASSESSMENT": "EVALUACIÓN DE SQLMAP",
        "No SQLMap result was returned.": "SQLMap no devolvió resultados.",
        "ITEM": "ELEMENTO",
        "RESULT": "RESULTADO",
        "ENGINE": "MOTOR",
        "DBMS": "SGBD",
        "Not confirmed": "No confirmado",
        "Not detected": "No detectado",
        "DATABASES FOUND": "BASES DE DATOS ENCONTRADAS",
        "None reported": "Ninguna indicada",
        "INJECTION": "INYECCIÓN",
        "SQL injection evidence detected": "Se detectaron indicios de inyección SQL",
        "No SQL injection confirmed": "No se confirmó ninguna inyección SQL",
        "NETWORK SCAN": "ANÁLISIS DE RED",
        "Port & Network Results": "Resultados de puertos y red",
        "RESULTS": "RESULTADOS",
        "STATUS": "ESTADO",
        "No structured port results were returned. Check the raw output below.": "No se devolvieron resultados estructurados de puertos. Comprueba la salida original a continuación.",
        "Scan Result": "Resultado del análisis",
        "SCAN RESULTS": "RESULTADOS DEL ANÁLISIS",
        "SCAN INFORMATION": "INFORMACIÓN DEL ANÁLISIS",
        "This scan checks host reachability and does not perform a TCP/UDP port scan.": "Este análisis comprueba la conectividad del host y no realiza un análisis de puertos TCP/UDP.",
        "PORT / ITEM": "PUERTO / ELEMENTO",
        "SERVICE / RESULT": "SERVICIO / RESULTADO",
        "No structured results were returned. Check the raw Nmap output below.": "No se devolvieron resultados estructurados. Comprueba la salida original de Nmap a continuación.",
        "Recent Operations": "Operaciones recientes",
        "SCAN TYPE": "TIPO DE ANÁLISIS",
        "ACTIVE": "ACTIVO",
        "Global Cyber Threat Map": "Mapa global de ciberamenazas",
        "LIVE ROTATION": "ROTACIÓN EN DIRECTO",
        "[CRITICAL] Suspicious traffic detected from Russia": "[CRÍTICO] Se detectó tráfico sospechoso procedente de Rusia",
        "[WARNING] SSH brute-force attempt detected": "[ADVERTENCIA] Se detectó un intento de fuerza bruta SSH",
        "[INFO] Firewall successfully blocked malicious IP": "[INFO] El cortafuegos bloqueó correctamente una IP maliciosa",
        "Nikto Web Security Findings": "Hallazgos de seguridad web de Nikto",
        "No Nikto findings detected.": "No se detectaron hallazgos de Nikto.",
        "SQLMap SQL Injection Assessment": "Evaluación de inyección SQL con SQLMap",
        "ASSESSMENT": "EVALUACIÓN",
        "Detected Services & Ports": "Servicios y puertos detectados",
        "LIVE THREAT TERMINAL": "TERMINAL DE AMENAZAS EN DIRECTO",
        "ATTACK REPLAY HERE": "REPRODUCCIÓN DEL ATAQUE",
        "Attack Replay Timeline": "Cronología de reproducción del ataque",
        "Historical attack sequence reconstruction": "Reconstrucción histórica de la secuencia del ataque",
        "START REPLAY": "INICIAR REPRODUCCIÓN",
        "Reconnaissance Detected": "Reconocimiento detectado",
        "SSH Service Exposure": "Exposición del servicio SSH",
        "Vulnerability Correlation": "Correlación de vulnerabilidades",
        "AI Threat Analysis": "Análisis de amenazas mediante IA",
        "AI engine generated mitigation recommendations": "El motor de IA generó recomendaciones de mitigación",
        "Quantum Shield AI Agent": "Agente de IA de Quantum Shield",
        "SEND": "ENVIAR"
    },

    fr: {
        "Dashboard Home": "Accueil du tableau de bord",
        "Threat Intelligence": "Renseignement sur les menaces",
        "Threat Intelligence (AI)": "Renseignement sur les menaces (IA)",
        "Network Reconnaissance": "Reconnaissance réseau",
        "Vulnerability Analysis": "Analyse des vulnérabilités",
        "Infrastructure Monitoring": "Surveillance de l’infrastructure",
        "Threat Dashboard": "Tableau de bord des menaces",
        "Scan History": "Historique des analyses",
        "AI Security Assistant": "Assistant de sécurité IA",
        "Scan Configuration": "Configuration de l’analyse",
        "System Settings": "Paramètres système",
        "Settings": "Paramètres",
        "Logout": "Déconnexion",
        "Dashboard": "Tableau de bord",
        "Security Dashboard": "Tableau de bord de sécurité",
        "Customize platform scanner presets, export templates, and security behavior.": "Personnalisez les profils du scanner, les modèles d’exportation et les paramètres de sécurité.",
        "Quick Scan": "Analyse rapide",
        "Launch Scan": "Lancer l’analyse",
        "Start Scan": "Démarrer l’analyse",
        "Scan Results": "Résultats de l’analyse",
        "Download PDF Report": "Télécharger le rapport PDF",
        "Reset Defaults": "Réinitialiser les valeurs",
        "Save Global Settings": "Enregistrer les paramètres",
        "Back to Dashboard Home": "Retour au tableau de bord",
        "Scanner Configuration": "Configuration du scanner",
        "Default Scan Preset": "Profil d’analyse par défaut",
        "Preset scan mode chosen upon startup.": "Mode d’analyse choisi au démarrage.",
        "Scan Timeout Limit": "Délai maximal de l’analyse",
        "Max waiting duration per network task.": "Durée maximale d’attente pour chaque tâche réseau.",
        "Aggressiveness Level": "Niveau d’agressivité",
        "Timing template (-T setting).": "Paramètre de temporisation (-T).",
        "Report & Export Formatting": "Format des rapports et des exports",
        "Enforced Export Format": "Format d’exportation imposé",
        "Primary file type format for downloaded reports.": "Format principal des rapports téléchargés.",
        "Include AI Summary Matrix": "Inclure le résumé IA",
        "Append AI-driven security tips to reports.": "Ajouter des conseils de sécurité générés par IA aux rapports.",
        "Include Raw Terminal Logs": "Inclure les journaux du terminal",
        "Attach command line output in report appendix.": "Joindre la sortie de la ligne de commande en annexe.",
        "Security & Interface Options": "Options de sécurité et d’interface",
        "Display Language": "Langue d’affichage",
        "Select the user interface display language.": "Sélectionnez la langue de l’interface.",
        "Interface Theme Color": "Couleur du thème de l’interface",
        "Accent layout style for your panels.": "Style de couleur des panneaux.",
        "Strict Target Input Sanitization": "Validation stricte de la cible",
        "Block invalid IP or domain structures automatically.": "Bloquer automatiquement les adresses IP ou domaines invalides.",
        "Settings saved successfully!": "Paramètres enregistrés avec succès !",
        "English": "Anglais",
        "Español (Spanish)": "Espagnol",
        "Français (French)": "Français",
        "Deutsch (German)": "Allemand",
        "TCP SYN / Stealth Scan": "Analyse TCP SYN / furtive",
        "TCP Connect Scan": "Analyse de connexion TCP",
        "TCP ACK Scan": "Analyse TCP ACK",
        "TCP Window Scan": "Analyse de fenêtre TCP",
        "TCP Maimon Scan": "Analyse TCP Maimon",
        "TCP FIN Scan": "Analyse TCP FIN",
        "TCP NULL Scan": "Analyse TCP NULL",
        "TCP Xmas Scan": "Analyse TCP Xmas",
        "UDP Scan": "Analyse UDP",
        "IP Protocol Scan": "Analyse du protocole IP",
        "Custom TCP Flag Scan": "Analyse avec indicateurs TCP personnalisés",
        "Idle Scan": "Analyse inactive",
        "FTP Bounce Scan": "Analyse FTP Bounce",
        "OS Detection": "Détection du système d’exploitation",
        "Intense Scan": "Analyse intensive",
        "All TCP Ports Scan": "Analyse de tous les ports TCP",
        "Ping / Host Discovery": "Ping / découverte d’hôte",
        "Vulnerability Scan": "Analyse des vulnérabilités",
        "Service Version Detection (-sV --version-intensity 5)": "Détection des versions des services (-sV --version-intensity 5)",
        "Default Web Script Scan (-sV -sC)": "Analyse web avec scripts par défaut (-sV -sC)",
        "Vulnerability Detection Script (--script vuln)": "Script de détection des vulnérabilités (--script vuln)",
        "Web Directory Brute-Forcing (--script http-enum)": "Force brute des répertoires web (--script http-enum)",
        "SSL/TLS Security Auditing (--script ssl-enum-ciphers)": "Audit de sécurité SSL/TLS (--script ssl-enum-ciphers)",
        "Comprehensive Web Auditing (--script \"http-*\")": "Audit web complet (--script \"http-*\")",
        "Nikto Web Scan": "Analyse web avec Nikto",
        "SQLMap Detection Scan": "Analyse de détection SQLMap",
        "When to Use:": "Quand l’utiliser :",
        "Pros:": "Avantages :",
        "Cons:": "Inconvénients :",
        "Very fast and efficient.": "Très rapide et efficace.",
        "Network Recon": "Reconnaissance réseau",
        "Threat Analysis": "Analyse des menaces",
        "Threat Engine Online": "Moteur de menaces en ligne",
        "AI Monitoring Active": "Surveillance IA active",
        "SOC Infrastructure Stable": "Infrastructure SOC stable",
        "EXECUTE": "EXÉCUTER",
        "AI CHAT": "CHAT IA",
        "Initializing Threat Intelligence Engine...": "Initialisation du moteur de renseignement sur les menaces...",
        "HOST STATUS": "ÉTAT DE L’HÔTE",
        "OS DETECTION": "DÉTECTION DU SYSTÈME",
        "SERVICES DETECTED": "SERVICES DÉTECTÉS",
        "VULNERABILITY FINDINGS": "VULNÉRABILITÉS DÉTECTÉES",
        "PROTOCOLS DETECTED": "PROTOCOLES DÉTECTÉS",
        "WEB FINDINGS": "RÉSULTATS WEB",
        "OPEN PORTS": "PORTS OUVERTS",
        "THREAT SCORE": "SCORE DE MENACE",
        "THREAT LEVEL": "NIVEAU DE MENACE",
        "SCAN STATUS": "ÉTAT DE L’ANALYSE",
        "COMPLETE": "TERMINÉ",
        "Threat Distribution": "Répartition des menaces",
        "NO THREAT FINDINGS": "AUCUNE MENACE DÉTECTÉE",
        "This scan returned no risk-rated findings.": "Cette analyse n’a révélé aucun résultat classé par niveau de risque.",
        "Scan Timeline": "Chronologie de l’analyse",
        "CVE Intelligence Feed": "Flux de renseignement CVE",
        "No CVE references were reported by this scan.": "Aucune référence CVE n’a été signalée par cette analyse.",
        "Web Security Recommendations": "Recommandations de sécurité web",
        "AI Security Recommendations": "Recommandations de sécurité IA",
        "Disable unused exposed services": "Désactiver les services exposés inutilisés",
        "Harden SSH configuration policies": "Renforcer la configuration SSH",
        "Upgrade outdated services": "Mettre à jour les services obsolètes",
        "Enable WAF and firewall filtering": "Activer le filtrage WAF et pare-feu",
        "Schedule recurring vulnerability assessments": "Planifier des évaluations régulières des vulnérabilités",
        "SCAN INTELLIGENCE": "RENSEIGNEMENT SUR L’ANALYSE",
        "Current Scan": "Analyse actuelle",
        "Only results from the scan you performed are displayed.": "Seuls les résultats de l’analyse effectuée sont affichés.",
        "QUICK SCAN": "ANALYSE RAPIDE",
        "Network Exposure": "Exposition réseau",
        "SERVICES": "SERVICES",
        "TARGET": "CIBLE",
        "PORT": "PORT",
        "STATE": "ÉTAT",
        "SERVICE": "SERVICE",
        "No open ports detected.": "Aucun port ouvert détecté.",
        "VERSION DETECTION": "DÉTECTION DES VERSIONS",
        "Service Intelligence": "Renseignement sur les services",
        "VERSIONS FOUND": "VERSIONS TROUVÉES",
        "No service/version information detected.": "Aucune information sur les services ou versions n’a été détectée.",
        "Target Fingerprint": "Empreinte de la cible",
        "DETECTED OS": "SYSTÈME DÉTECTÉ",
        "DEVICE TYPE": "TYPE D’APPAREIL",
        "CONFIDENCE": "CONFIANCE",
        "OS ANALYSIS": "ANALYSE DU SYSTÈME",
        "Not detected": "Non détecté",
        "Unknown": "Inconnu",
        "No operating-system information was returned.": "Aucune information sur le système d’exploitation n’a été renvoyée.",
        "VULNERABILITY SCAN": "ANALYSE DES VULNÉRABILITÉS",
        "Threat Assessment": "Évaluation des menaces",
        "HIGH": "ÉLEVÉ",
        "MEDIUM": "MOYEN",
        "LOW": "FAIBLE",
        "CVE REFERENCES FROM THIS SCAN": "RÉFÉRENCES CVE DE CETTE ANALYSE",
        "RISK": "RISQUE",
        "SCAN DESCRIPTION": "DESCRIPTION DE L’ANALYSE",
        "TARGET WEB SERVER": "SERVEUR WEB CIBLE",
        "CVE REFERENCES REPORTED BY NIKTO": "RÉFÉRENCES CVE SIGNALÉES PAR NIKTO",
        "CVE REFERENCES": "RÉFÉRENCES CVE",
        "No CVE references were reported in the Nikto output.": "Aucune référence CVE n’a été signalée dans la sortie de Nikto.",
        "FINDING": "RÉSULTAT",
        "No Nikto findings were returned for this target.": "Nikto n’a renvoyé aucun résultat pour cette cible.",
        "SQL Injection Assessment": "Évaluation de l’injection SQL",
        "Deep SQL Injection Assessment": "Évaluation approfondie de l’injection SQL",
        "Database Fingerprint": "Empreinte de la base de données",
        "Database Enumeration": "Énumération des bases de données",
        "RISK LEVEL": "NIVEAU DE RISQUE",
        "SCAN MODE": "MODE D’ANALYSE",
        "SQLMAP TARGET URL": "URL CIBLE SQLMAP",
        "SQLMAP ASSESSMENT": "ÉVALUATION SQLMAP",
        "No SQLMap result was returned.": "SQLMap n’a renvoyé aucun résultat.",
        "ITEM": "ÉLÉMENT",
        "RESULT": "RÉSULTAT",
        "ENGINE": "MOTEUR",
        "DBMS": "SGBD",
        "DATABASES FOUND": "BASES DE DONNÉES TROUVÉES",
        "None reported": "Aucune indiquée",
        "INJECTION": "INJECTION",
        "SQL injection evidence detected": "Des indices d’injection SQL ont été détectés",
        "No SQL injection confirmed": "Aucune injection SQL confirmée",
        "NETWORK SCAN": "ANALYSE RÉSEAU",
        "Port & Network Results": "Résultats des ports et du réseau",
        "RESULTS": "RÉSULTATS",
        "STATUS": "STATUT",
        "No structured port results were returned. Check the raw output below.": "Aucun résultat structuré de ports n’a été renvoyé. Consultez la sortie brute ci-dessous.",
        "Scan Result": "Résultat de l’analyse",
        "SCAN RESULTS": "RÉSULTATS DE L’ANALYSE",
        "SCAN INFORMATION": "INFORMATIONS SUR L’ANALYSE",
        "This scan checks host reachability and does not perform a TCP/UDP port scan.": "Cette analyse vérifie la disponibilité de l’hôte sans analyser les ports TCP/UDP.",
        "PORT / ITEM": "PORT / ÉLÉMENT",
        "SERVICE / RESULT": "SERVICE / RÉSULTAT",
        "No structured results were returned. Check the raw Nmap output below.": "Aucun résultat structuré n’a été renvoyé. Consultez la sortie brute de Nmap ci-dessous.",
        "Recent Operations": "Opérations récentes",
        "SCAN TYPE": "TYPE D’ANALYSE",
        "ACTIVE": "ACTIF",
        "Global Cyber Threat Map": "Carte mondiale des cybermenaces",
        "LIVE ROTATION": "ROTATION EN DIRECT",
        "Nikto Web Security Findings": "Résultats de sécurité web Nikto",
        "No Nikto findings detected.": "Aucun résultat Nikto détecté.",
        "SQLMap SQL Injection Assessment": "Évaluation de l’injection SQL avec SQLMap",
        "ASSESSMENT": "ÉVALUATION",
        "Detected Services & Ports": "Services et ports détectés",
        "LIVE THREAT TERMINAL": "TERMINAL DES MENACES EN DIRECT",
        "ATTACK REPLAY HERE": "RELECTURE DE L’ATTAQUE",
        "Attack Replay Timeline": "Chronologie de relecture de l’attaque",
        "Historical attack sequence reconstruction": "Reconstitution historique de la séquence d’attaque",
        "START REPLAY": "DÉMARRER LA RELECTURE",
        "Reconnaissance Detected": "Reconnaissance détectée",
        "SSH Service Exposure": "Exposition du service SSH",
        "Vulnerability Correlation": "Corrélation des vulnérabilités",
        "AI Threat Analysis": "Analyse des menaces par IA",
        "AI engine generated mitigation recommendations": "Le moteur IA a généré des recommandations d’atténuation",
        "Quantum Shield AI Agent": "Agent IA Quantum Shield",
        "SEND": "ENVOYER"
    },

    de: {
        "Dashboard Home": "Dashboard-Startseite",
        "Threat Intelligence": "Bedrohungsanalyse",
        "Threat Intelligence (AI)": "Bedrohungsanalyse (KI)",
        "Network Reconnaissance": "Netzwerkerkundung",
        "Vulnerability Analysis": "Schwachstellenanalyse",
        "Infrastructure Monitoring": "Infrastrukturüberwachung",
        "Threat Dashboard": "Bedrohungs-Dashboard",
        "Scan History": "Scan-Verlauf",
        "AI Security Assistant": "KI-Sicherheitsassistent",
        "Scan Configuration": "Scan-Konfiguration",
        "System Settings": "Systemeinstellungen",
        "Settings": "Einstellungen",
        "Logout": "Abmelden",
        "Dashboard": "Dashboard",
        "Security Dashboard": "Sicherheits-Dashboard",
        "Customize platform scanner presets, export templates, and security behavior.": "Passen Sie Scannerprofile, Exportvorlagen und Sicherheitseinstellungen an.",
        "Quick Scan": "Schneller Scan",
        "Launch Scan": "Scan starten",
        "Start Scan": "Scan starten",
        "Scan Results": "Scan-Ergebnisse",
        "Download PDF Report": "PDF-Bericht herunterladen",
        "Reset Defaults": "Standards wiederherstellen",
        "Save Global Settings": "Globale Einstellungen speichern",
        "Back to Dashboard Home": "Zurück zum Dashboard",
        "Scanner Configuration": "Scanner-Konfiguration",
        "Default Scan Preset": "Standard-Scanprofil",
        "Preset scan mode chosen upon startup.": "Beim Start ausgewählter Scanmodus.",
        "Scan Timeout Limit": "Scan-Zeitlimit",
        "Max waiting duration per network task.": "Maximale Wartezeit pro Netzwerkaufgabe.",
        "Aggressiveness Level": "Aggressivitätsstufe",
        "Timing template (-T setting).": "Timing-Einstellung (-T).",
        "Report & Export Formatting": "Berichts- und Exportformatierung",
        "Enforced Export Format": "Vorgeschriebenes Exportformat",
        "Primary file type format for downloaded reports.": "Primäres Dateiformat für heruntergeladene Berichte.",
        "Include AI Summary Matrix": "KI-Zusammenfassung einschließen",
        "Append AI-driven security tips to reports.": "KI-generierte Sicherheitshinweise an Berichte anhängen.",
        "Include Raw Terminal Logs": "Terminalprotokolle einschließen",
        "Attach command line output in report appendix.": "Kommandozeilenausgabe im Berichtsanhang hinzufügen.",
        "Security & Interface Options": "Sicherheits- und Oberflächenoptionen",
        "Display Language": "Anzeigesprache",
        "Select the user interface display language.": "Wählen Sie die Sprache der Benutzeroberfläche.",
        "Interface Theme Color": "Farbe des Oberflächenthemas",
        "Accent layout style for your panels.": "Akzentstil für Ihre Bedienfelder.",
        "Strict Target Input Sanitization": "Strenge Zielvalidierung",
        "Block invalid IP or domain structures automatically.": "Ungültige IP-Adressen oder Domains automatisch blockieren.",
        "Settings saved successfully!": "Einstellungen erfolgreich gespeichert!",
        "English": "Englisch",
        "Español (Spanish)": "Spanisch",
        "Français (French)": "Französisch",
        "Deutsch (German)": "Deutsch",
        "TCP SYN / Stealth Scan": "TCP-SYN- / Stealth-Scan",
        "TCP Connect Scan": "TCP-Verbindungs-Scan",
        "TCP ACK Scan": "TCP-ACK-Scan",
        "TCP Window Scan": "TCP-Window-Scan",
        "TCP Maimon Scan": "TCP-Maimon-Scan",
        "TCP FIN Scan": "TCP-FIN-Scan",
        "TCP NULL Scan": "TCP-NULL-Scan",
        "TCP Xmas Scan": "TCP-Xmas-Scan",
        "UDP Scan": "UDP-Scan",
        "IP Protocol Scan": "IP-Protokoll-Scan",
        "Custom TCP Flag Scan": "Scan mit benutzerdefinierten TCP-Flags",
        "Idle Scan": "Idle-Scan",
        "FTP Bounce Scan": "FTP-Bounce-Scan",
        "OS Detection": "Betriebssystemerkennung",
        "Intense Scan": "Intensiver Scan",
        "All TCP Ports Scan": "Scan aller TCP-Ports",
        "Ping / Host Discovery": "Ping / Host-Erkennung",
        "Vulnerability Scan": "Schwachstellenscan",
        "Service Version Detection (-sV --version-intensity 5)": "Dienstversionserkennung (-sV --version-intensity 5)",
        "Default Web Script Scan (-sV -sC)": "Webscan mit Standardskripten (-sV -sC)",
        "Vulnerability Detection Script (--script vuln)": "Schwachstellenerkennungsskript (--script vuln)",
        "Web Directory Brute-Forcing (--script http-enum)": "Brute-Force für Webverzeichnisse (--script http-enum)",
        "SSL/TLS Security Auditing (--script ssl-enum-ciphers)": "SSL/TLS-Sicherheitsaudit (--script ssl-enum-ciphers)",
        "Comprehensive Web Auditing (--script \"http-*\")": "Umfassendes Webaudit (--script \"http-*\")",
        "Nikto Web Scan": "Nikto-Webscan",
        "SQLMap Detection Scan": "SQLMap-Erkennungsscan",
        "When to Use:": "Wann verwenden:",
        "Pros:": "Vorteile:",
        "Cons:": "Nachteile:",
        "Very fast and efficient.": "Sehr schnell und effizient.",
        "Network Recon": "Netzwerkerkundung",
        "Threat Analysis": "Bedrohungsanalyse",
        "Threat Engine Online": "Bedrohungsmodul online",
        "AI Monitoring Active": "KI-Überwachung aktiv",
        "SOC Infrastructure Stable": "SOC-Infrastruktur stabil",
        "EXECUTE": "AUSFÜHREN",
        "AI CHAT": "KI-CHAT",
        "Initializing Threat Intelligence Engine...": "Bedrohungsanalysemodul wird initialisiert...",
        "HOST STATUS": "HOST-STATUS",
        "OS DETECTION": "BETRIEBSSYSTEMERKENNUNG",
        "SERVICES DETECTED": "ERKANNTE DIENSTE",
        "VULNERABILITY FINDINGS": "GEFUNDENE SCHWACHSTELLEN",
        "PROTOCOLS DETECTED": "ERKANNTE PROTOKOLLE",
        "WEB FINDINGS": "WEB-BEFUNDE",
        "OPEN PORTS": "OFFENE PORTS",
        "THREAT SCORE": "BEDROHUNGSWERT",
        "THREAT LEVEL": "BEDROHUNGSSTUFE",
        "SCAN STATUS": "SCAN-STATUS",
        "COMPLETE": "ABGESCHLOSSEN",
        "Threat Distribution": "Bedrohungsverteilung",
        "NO THREAT FINDINGS": "KEINE BEDROHUNGEN GEFUNDEN",
        "This scan returned no risk-rated findings.": "Dieser Scan ergab keine nach Risiko eingestuften Befunde.",
        "Scan Timeline": "Scan-Zeitachse",
        "CVE Intelligence Feed": "CVE-Informationsfeed",
        "No CVE references were reported by this scan.": "Dieser Scan meldete keine CVE-Referenzen.",
        "Web Security Recommendations": "Web-Sicherheitsempfehlungen",
        "AI Security Recommendations": "KI-Sicherheitsempfehlungen",
        "Disable unused exposed services": "Nicht verwendete exponierte Dienste deaktivieren",
        "Harden SSH configuration policies": "SSH-Konfiguration absichern",
        "Upgrade outdated services": "Veraltete Dienste aktualisieren",
        "Enable WAF and firewall filtering": "WAF- und Firewall-Filterung aktivieren",
        "Schedule recurring vulnerability assessments": "Regelmäßige Schwachstellenprüfungen planen",
        "SCAN INTELLIGENCE": "SCAN-INTELLIGENZ",
        "Current Scan": "Aktueller Scan",
        "Only results from the scan you performed are displayed.": "Es werden nur Ergebnisse des durchgeführten Scans angezeigt.",
        "QUICK SCAN": "SCHNELLER SCAN",
        "Network Exposure": "Netzwerkexposition",
        "SERVICES": "DIENSTE",
        "TARGET": "ZIEL",
        "PORT": "PORT",
        "STATE": "STATUS",
        "SERVICE": "DIENST",
        "No open ports detected.": "Keine offenen Ports erkannt.",
        "VERSION DETECTION": "VERSIONserkennung",
        "Service Intelligence": "Dienstinformationen",
        "VERSIONS FOUND": "GEFUNDENE VERSIONEN",
        "No service/version information detected.": "Keine Dienst- oder Versionsinformationen erkannt.",
        "Target Fingerprint": "Ziel-Fingerabdruck",
        "DETECTED OS": "ERKANNTES BETRIEBSSYSTEM",
        "DEVICE TYPE": "GERÄTETYP",
        "CONFIDENCE": "SICHERHEIT",
        "OS ANALYSIS": "BETRIEBSSYSTEMANALYSE",
        "Not detected": "Nicht erkannt",
        "Unknown": "Unbekannt",
        "No operating-system information was returned.": "Es wurden keine Betriebssysteminformationen zurückgegeben.",
        "VULNERABILITY SCAN": "SCHWACHSTELLENSCAN",
        "Threat Assessment": "Bedrohungsbewertung",
        "HIGH": "HOCH",
        "MEDIUM": "MITTEL",
        "LOW": "NIEDRIG",
        "CVE REFERENCES FROM THIS SCAN": "CVE-REFERENZEN DIESES SCANS",
        "RISK": "RISIKO",
        "SCAN DESCRIPTION": "SCAN-BESCHREIBUNG",
        "TARGET WEB SERVER": "WEB-ZIELSERVER",
        "CVE REFERENCES REPORTED BY NIKTO": "VON NIKTO GEMELDETE CVE-REFERENZEN",
        "CVE REFERENCES": "CVE-REFERENZEN",
        "No CVE references were reported in the Nikto output.": "Die Nikto-Ausgabe enthielt keine CVE-Referenzen.",
        "FINDING": "BEFUND",
        "No Nikto findings were returned for this target.": "Nikto meldete keine Befunde für dieses Ziel.",
        "SQL Injection Assessment": "SQL-Injection-Bewertung",
        "Deep SQL Injection Assessment": "Erweiterte SQL-Injection-Bewertung",
        "Database Fingerprint": "Datenbank-Fingerabdruck",
        "Database Enumeration": "Datenbankaufzählung",
        "RISK LEVEL": "RISIKOSTUFE",
        "SCAN MODE": "SCAN-MODUS",
        "SQLMAP TARGET URL": "SQLMAP-ZIEL-URL",
        "SQLMAP ASSESSMENT": "SQLMAP-BEWERTUNG",
        "No SQLMap result was returned.": "SQLMap lieferte kein Ergebnis.",
        "ITEM": "ELEMENT",
        "RESULT": "ERGEBNIS",
        "ENGINE": "ENGINE",
        "DBMS": "DBMS",
        "DATABASES FOUND": "GEFUNDENE DATENBANKEN",
        "None reported": "Keine angegeben",
        "INJECTION": "INJEKTION",
        "SQL injection evidence detected": "Hinweise auf SQL-Injection erkannt",
        "No SQL injection confirmed": "Keine SQL-Injection bestätigt",
        "NETWORK SCAN": "NETZWERKSCAN",
        "Port & Network Results": "Port- und Netzwerkergebnisse",
        "RESULTS": "ERGEBNISSE",
        "STATUS": "STATUS",
        "No structured port results were returned. Check the raw output below.": "Es wurden keine strukturierten Port-Ergebnisse zurückgegeben. Prüfen Sie die Rohdaten unten.",
        "Scan Result": "Scan-Ergebnis",
        "SCAN RESULTS": "SCAN-ERGEBNISSE",
        "SCAN INFORMATION": "SCAN-INFORMATIONEN",
        "This scan checks host reachability and does not perform a TCP/UDP port scan.": "Dieser Scan prüft die Erreichbarkeit des Hosts und führt keinen TCP/UDP-Portscan durch.",
        "PORT / ITEM": "PORT / ELEMENT",
        "SERVICE / RESULT": "DIENST / ERGEBNIS",
        "No structured results were returned. Check the raw Nmap output below.": "Es wurden keine strukturierten Ergebnisse zurückgegeben. Prüfen Sie die Nmap-Rohdaten unten.",
        "Recent Operations": "Letzte Vorgänge",
        "SCAN TYPE": "SCAN-TYP",
        "ACTIVE": "AKTIV",
        "Global Cyber Threat Map": "Globale Cyberbedrohungskarte",
        "LIVE ROTATION": "LIVE-ROTATION",
        "Nikto Web Security Findings": "Nikto-Websicherheitsbefunde",
        "No Nikto findings detected.": "Keine Nikto-Befunde erkannt.",
        "SQLMap SQL Injection Assessment": "SQL-Injection-Bewertung mit SQLMap",
        "ASSESSMENT": "BEWERTUNG",
        "Detected Services & Ports": "Erkannte Dienste und Ports",
        "LIVE THREAT TERMINAL": "LIVE-BEDROHUNGSTERMINAL",
        "ATTACK REPLAY HERE": "ANGRIFFSWIEDERGABE",
        "Attack Replay Timeline": "Zeitachse der Angriffswiedergabe",
        "Historical attack sequence reconstruction": "Rekonstruktion des historischen Angriffsablaufs",
        "START REPLAY": "WIEDERGABE STARTEN",
        "Reconnaissance Detected": "Aufklärung erkannt",
        "SSH Service Exposure": "SSH-Dienst offengelegt",
        "Vulnerability Correlation": "Schwachstellenkorrelation",
        "AI Threat Analysis": "KI-Bedrohungsanalyse",
        "AI engine generated mitigation recommendations": "Die KI hat Empfehlungen zur Risikominderung erstellt",
        "Quantum Shield AI Agent": "Quantum-Shield-KI-Agent",
        "SEND": "SENDEN"
    }
};


// ------------------------------------------------------
// 2. REMEMBER ORIGINAL TEXT
// ------------------------------------------------------

// These maps save the original English text so the page
// can switch languages without translating translations.

const originalText = new WeakMap();
const originalAttributes = new WeakMap();


// ------------------------------------------------------
// 3. TRANSLATE A STRING
// ------------------------------------------------------

function translateString(text, dictionary) {
    let result = text;

    // Longer phrases are translated first.
    const phrases = Object.keys(dictionary).sort(
        (a, b) => b.length - a.length
    );

    for (const phrase of phrases) {
        result = result.split(phrase).join(dictionary[phrase]);
    }

    return result;
}


// ------------------------------------------------------
// 4. TRANSLATE A TEXT NODE
// ------------------------------------------------------

function translateTextNode(node, language) {
    const dictionary = translations[language] || {};

    if (!originalText.has(node)) {
        originalText.set(node, node.nodeValue);
    }

    const englishText = originalText.get(node);

    // Keep the original English text when English is selected.
    if (language === "en") {
        node.nodeValue = englishText;
        return;
    }

    node.nodeValue = translateString(englishText, dictionary);
}


// ------------------------------------------------------
// 5. TRANSLATE PLACEHOLDERS AND ACCESSIBILITY LABELS
// ------------------------------------------------------

function translateAttributes(element, language) {
    const dictionary = translations[language] || {};

    const names = ["placeholder", "title", "aria-label"];

    if (!originalAttributes.has(element)) {
        const saved = {};

        names.forEach(function (name) {
            saved[name] = element.getAttribute(name);
        });

        originalAttributes.set(element, saved);
    }

    const saved = originalAttributes.get(element);

    names.forEach(function (name) {
        const originalValue = saved[name];

        if (originalValue === null) {
            return;
        }

        if (language === "en") {
            element.setAttribute(name, originalValue);
        } else {
            element.setAttribute(
                name,
                translateString(originalValue, dictionary)
            );
        }
    });
}


// ------------------------------------------------------
// 6. TRANSLATE AN ELEMENT AND ITS CHILDREN
// ------------------------------------------------------

function translateElement(element, language) {
    if (!element) {
        return;
    }

    // Do not translate JavaScript or CSS source code.
    if (
        element.tagName === "SCRIPT" ||
        element.tagName === "STYLE" ||
        element.tagName === "NOSCRIPT"
    ) {
        return;
    }

    // Translate text inside this element.
    element.childNodes.forEach(function (node) {
        if (node.nodeType === Node.TEXT_NODE) {
            translateTextNode(node, language);
        } else if (node.nodeType === Node.ELEMENT_NODE) {
            translateElement(node, language);
        }
    });

    // Translate placeholders, titles, and labels.
    translateAttributes(element, language);
}


// ------------------------------------------------------
// 7. CHANGE THE WEBSITE LANGUAGE
// ------------------------------------------------------

let currentLanguage = "en";

function changeLanguage(language) {
    // Only allow languages defined in the dictionary.
    if (!translations[language]) {
        language = "en";
    }

    currentLanguage = language;

    // Translate the page from the body down.
    translateElement(document.body, language);

    // Update the language setting in the HTML.
    document.documentElement.lang = language;

    // Remember the selected language.
    localStorage.setItem("preferred_language", language);
}


// ------------------------------------------------------
// 8. HANDLE TEXT THAT APPEARS LATER
// ------------------------------------------------------

// Scan results, alerts, and chat messages can be added
// after the page loads. This observer translates new content.

const pageObserver = new MutationObserver(function (changes) {
    changes.forEach(function (change) {

        // Translate newly added text.
        change.addedNodes.forEach(function (node) {
            if (node.nodeType === Node.TEXT_NODE) {
                const parent = node.parentElement;

                if (
                    parent &&
                    !["SCRIPT", "STYLE", "NOSCRIPT"].includes(parent.tagName)
                ) {
                    translateTextNode(node, currentLanguage);
                }
            }

            // Translate newly added HTML elements.
            if (node.nodeType === Node.ELEMENT_NODE) {
                translateElement(node, currentLanguage);
            }
        });
    });
});


// ------------------------------------------------------
// 9. START WHEN THE PAGE IS READY
// ------------------------------------------------------

document.addEventListener("DOMContentLoaded", function () {
    const dropdown = document.getElementById("displayLanguage");

    // Use the saved language, or English if none is saved.
    const savedLanguage =
        localStorage.getItem("preferred_language") || "en";

    // Set up the language dropdown.
    if (dropdown) {
        dropdown.value = savedLanguage;

        dropdown.addEventListener("change", function () {
            changeLanguage(dropdown.value);
        });
    }

    // Translate the page when it first opens.
    changeLanguage(savedLanguage);

    // Watch for new content added by the website.
    pageObserver.observe(document.body, {
        childList: true,
        subtree: true
    });
});