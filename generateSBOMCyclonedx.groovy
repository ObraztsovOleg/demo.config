def getDefaultConfig() {
    return [
            stage      : "pack",
            phase      : "before",
            description: "Анализ зависимостей сборочных проектов"
    ]
}

def wrapNodejs(def config, extension, def closure) {
    def result = closure
    def npmVersion = extension.npm?.version ?: config.npm?.version ?: "node-v20.12.2"
    def npmConfigId = extension.npm?.config_id ?: config.npm?.config_id
    if (config.npm) {
        result = {
            nodejs(nodeJSInstallationName: npmVersion, configId: npmConfigId) {
                closure()
            }
        }
    }
    return result
}

def wrapMaven(def config, extension, def closure) {
    def result = closure
    def mavenHome = extension.maven?.home ?: config.maven?.home
    def jdk = extension.maven?.jdk ?: config.maven?.jdk ?: "openjdk-21"
    def mavenSettingsConfig = extension.maven?.settings_id ?: config.maven?.settings_id
    def mavenLocalRepo = extension.maven?.local_repo ?: '$workspace/.m2'
    if (config.maven) {
        result = {
            withMaven(maven: mavenHome, jdk: jdk, mavenSettingsConfig: mavenSettingsConfig, mavenLocalRepo: mavenLocalRepo) {
                closure()
            }
        }
    }
    return result
}

def wrapMavenSettingsFile(def mavenSettingsId, def closure) {
    if (!mavenSettingsId) return closure

    return {
        configFileProvider([configFile(fileId: mavenSettingsId, variable: "MAVEN_SETTINGS_FILE")]) {
            closure()
        }
    }
}

def normalizeList(def value) {
    if (value == null) return []
    if (value instanceof String) return value.trim() ? [value.trim()] : []
    return value as List
}

def isExcludedDir(def path, def excludedDirs) {
    return excludedDirs.any { excluded ->
        path == excluded || path.startsWith("${excluded}/")
    }
}

def findPruneExpression(def excludedDirs) {
    if (!excludedDirs) return ""

    def expressions = excludedDirs.collect { excluded ->
        "-path \"${excluded}\" -o -path \"${excluded}/*\""
    }.join(" -o ")
    return "\\( ${expressions} \\) -prune -o"
}

def createSDKPomsFolder(def globals, def dirs, def excludedDirs = []) {
    def pomsDir = "${globals.DIR_TMP}/poms"
    def prune = findPruneExpression(excludedDirs)
    def findDirs = dirs.collect { "\"${it}\"" }.join(" ")
    def pomPaths = sh (
        script: "find ${findDirs} ${prune} -name '*.pom' -type f -print",
        returnStdout: true
    ).tokenize("\n")
    def poms = getPoms(pomPaths)
    def paths = createPaths(poms)

    dir(pomsDir) {
        createPomHirarchy(paths)
    }

    return pomsDir
}

void createPomHirarchy(def paths) {
    paths.each { info ->
        dir(info.dest){
            writeMavenPom(model: info.pom, file: "pom.xml")
        }
    }
}

def createPaths(def poms) {
    poms.collect { pomKey, pomInfo ->
        [pom: pomInfo.pom, dest: getDestPath(pomInfo, poms, pomKey)]
    }
}

def getDestPath(def pomInfo, def poms, def pomKey) {
    def parent = poms[pomInfo.parent]
    def dest = pomInfo.dir

    if (parent) {
        if (pomInfo.gav == pomKey) {
            parent.pom.addModule(dest)
        }

        dest = getDestPath(parent, poms, pomKey) + "/" + dest
    }

    return dest
}

def stablePathId(def path) {
    return UUID.randomUUID().toString()
}

def extractTgz(def dirs, def globals, def excludedDirs = []) {
    def tgzDir = "${globals.DIR_TMP}/tgz"
    def prune = findPruneExpression(excludedDirs)
    def findDirs = dirs.collect { "\"${it}\"" }.join(" ")
    def tgzPaths = sh (
        script: "find ${findDirs} ${prune} \\( -name '*.tgz' -o -name '*.tgz.gz' \\) -type f -print",
        returnStdout: true
    ).tokenize("\n")
    
    dir(tgzDir) {
        tgzPaths.each { tgzPath ->
            def objectFilePath = "${tgzDir}/${stablePathId(tgzPath)}"
            sh """
                rm -rf "${objectFilePath}"
                mkdir -p "${objectFilePath}"
                tar -xvzf "${tgzPath}" -C "${objectFilePath}"
            """
        }
    }

    return tgzDir
}

def getPoms(def pomPaths) {
    return pomPaths.collectEntries { path ->
        def pom = readMavenPom(file: path)
        def parentGav = [
            artifactId: pom.parent?.artifactId,
            groupId: pom.parent?.groupId,
            version: pom.parent?.version
        ]
        def pomGav = [
            artifactId: pom.artifactId ?: parentGav.artifactId,
            groupId: pom.groupId ?: parentGav.groupId, 
            version: pom.version ?: parentGav.version
        ]
        def pomKeyGav = "${pomGav.artifactId}:${pomGav.groupId}:${pomGav.version}".toString()
        def parentKeyGav = "${parentGav.artifactId}:${parentGav.groupId}:${parentGav.version}".toString()
        pom.setModules([])
        
        return [
            (pomKeyGav): [
                pom: pom,
                gav: pomKeyGav,
                dir: pomGav.artifactId,
                parent: parentKeyGav
            ] 
        ]
    }
}

void generateSBOMTemplate(String sbomTemplatePath, def gavtc, def code) {
    writeJSON file: sbomTemplatePath, json: [
        bomFormat: "CycloneDX",
        metadata: [
            component: [
                type: "application",
                group: gavtc.groupId,
                name: code,
                version: gavtc.version,
                purl: "pkg:maven/${gavtc.groupId}.${gavtc.artifactId}@${gavtc.version}"
            ]
        ],
        components: [],
        dependencies: []
    ]
}

def getProjectDirs(def globals, useNewVersion = null, def sourceDirs = null, def excludedDirs = []) {
    if (!fileExists(globals.DIR_SRC)) sh "mkdir -p ${globals.DIR_SRC}"

    sourceDirs = sourceDirs ?: getSourceDirs(globals)
    def activeSourceDirs = sourceDirs.findAll { !isExcludedDir(it, excludedDirs) }
    def baseDirs = [globals.DIR_SRC]
    if (fileExists(globals.DIR_SDK)) {
        baseDirs << globals.DIR_SDK
    }

    def analysisDirs = []
    if (useNewVersion) {
        analysisDirs += createSDKPomsFolder(globals, baseDirs, excludedDirs)
        analysisDirs += extractTgz(baseDirs, globals, excludedDirs)
    } else {
        analysisDirs += getGradlePaths(globals, excludedDirs)
        analysisDirs += activeSourceDirs
        analysisDirs += createSDKPomsFolder(globals, baseDirs, excludedDirs)
        analysisDirs += extractTgz(baseDirs, globals, excludedDirs)
    }

    def projectDirs = baseDirs + analysisDirs
    return projectDirs.flatten().unique()
}


def getExcluded(def sourceDirs, def sbomPaths) {
    def scannedReposWithReportPaths = [:]

    sourceDirs.each { directory ->
        def allFound = []

        sbomPaths.each { sbomPath ->
            def sbomAntName = sbomPath.startsWith(directory) ? sbomPath.minus(directory) : sbomPath
            def sbomFiles = sh (
                script: "find \"${directory}\" -path \"${directory}/${sbomAntName}\" -type f -not -empty",
                returnStdout: true
            ).tokenize("\n")
            
            allFound.addAll(sbomFiles)
        }

        def length = allFound.size()

        if (length == 1) {
            println("В репозитории ${directory} найден SBOM файл ${allFound.first()}. Данный файл будет использован вместо генерации SBOM компонента.")
            scannedReposWithReportPaths[directory] = allFound.first()
        } else if (length > 1) {
            unstable("Найдено несколько SBOM файлов в репозитории ${directory}. Будет произведено сканирование данной директории.")
        } else {
            println("SBOM файл в репозитории ${directory} не найден. Будет произведено сканирование данной директории.")
        }
    }

    return scannedReposWithReportPaths
}

def getTools(def extension) {
    def tools = [
        "CYCLONE=${tool name: extension.cdxgen ?: 'cdxgen-12.6.0'}",
        "CYClONE_CLI=${tool name: extension.cyclonedx_cli ?: 'cyclonedx-linux-x64-v0.27.1'}",
        "MVN_ARGS=${env.MVN_ARGS ?: '-DincludeProvidedScope=false'}",
        "CDX_MAVEN_INCLUDE_TEST_SCOPE=${env.CDX_MAVEN_INCLUDE_TEST_SCOPE ?: false}",
        "NODE_EXTRA_CA_CERTS=${env.NODE_EXTRA_CA_CERTS ?: env.TRUSTED_CERT_CHAIN_PATH ?: ''}"
    ]
    normalizeList(extension.tools).each { toolName ->
        def toolPath = tool name: toolName
        if (fileExists("${toolPath}/bin")) toolPath = "${toolPath}/bin"
        tools += "PATH+TOOL_PATH=${toolPath}"
    }

    return tools
}

def getEnvs(def extension) {
    return extension.env?.collect {key,value ->
        "$key=$value"
    } ?: []
}

def getMavenSettingsId(def config, def extension) {
    return extension.maven?.settings_id ?: config.maven?.settings_id
}

def dockerEnvExportLine(def key, def value) {
    def normalizedKey = key.toString().replaceAll(/[.-]/, "_")
    if (normalizedKey == "MAVEN_SETTINGS_FILE") return ""
    if (!(normalizedKey ==~ /[A-Za-z_][A-Za-z0-9_]*/)) return ""

    def normalizedValue = value.toString().replace("\r", "").replace("\n", "\\n")
    normalizedValue = normalizedValue.replace("'", "'\"'\"'")
    return "export ${normalizedKey}=\${${normalizedKey}:-'${normalizedValue}'}"
}

def getDockerEnvAssignments(def globals, def extensionEnvs) {
    def envFileName = "${globals.DIR_TMP}/generateSBOMCyclonedx-envParams-${UUID.randomUUID()}"
    def lines = sh(script: "env", returnStdout: true).split("\n").collect { line ->
        def separatorIndex = line.indexOf("=")
        if (separatorIndex < 0) return ""

        dockerEnvExportLine(line.substring(0, separatorIndex), line.substring(separatorIndex + 1))
    }

    lines += extensionEnvs.collect { envValue ->
        def text = envValue.toString()
        def separatorIndex = text.indexOf("=")
        if (separatorIndex < 0) return ""

        dockerEnvExportLine(text.substring(0, separatorIndex), text.substring(separatorIndex + 1))
    }

    writeFile file: envFileName, text: lines.findAll { it }.join("\n") + "\n"
    return envFileName
}

def getGradlePaths(def globals, def excludedDirs = []) {
    def prune = findPruneExpression(excludedDirs)
    return sh (
        script: "find \"${globals.DIR_SRC}\" ${prune} -name build.gradle -printf '%h\n'",
        returnStdout: true
    ).tokenize("\n")
}

def getSourceDirs(def globals, def excludedDirs = []) {
    if (!fileExists(globals.DIR_SRC)) return []

    def dirs = sh (
        script: "find ${globals.DIR_SRC} -maxdepth 1 -type d -not -path '${globals.DIR_SRC}' -not -empty",
        returnStdout: true
    ).tokenize("\n")
    return dirs.findAll { !isExcludedDir(it, excludedDirs) }
}

def findMavenProjectDirs(def sourceDirs, def excludedDirs = []) {
    def activeSourceDirs = sourceDirs.findAll { !isExcludedDir(it, excludedDirs) }
    if (!activeSourceDirs) return []

    def pomPaths = activeSourceDirs.collectMany { sourceDir ->
        sh(
            script: """
                set -e
                cd "${sourceDir}"
                find . \\( -path './target' -o -path './target/*' -o -path './build' -o -path './build/*' \\) -prune -o \\
                    -name 'pom.xml' -type f -print
            """,
            returnStdout: true
        ).tokenize("\n").collect { relativePath ->
            def normalizedRelativePath = relativePath.startsWith("./") ? relativePath.substring(2) : relativePath
            "${sourceDir}/${normalizedRelativePath}"
        }
    }.sort()

    def pomByDir = pomPaths.collectEntries { path ->
        [(path.substring(0, path.length() - "/pom.xml".length())): path]
    }
    def moduleDirs = [] as Set

    pomByDir.each { projectDir, pomPath ->
        def modules = []
        try {
            modules = normalizeList(readMavenPom(file: pomPath)?.modules)
        } catch (err) {
            echo("Не удалось прочитать Maven modules из ${pomPath}: ${err}")
        }

        modules.each { moduleValue ->
            def moduleName = moduleValue.toString().trim()
            if (moduleName) {
                def moduleDir = getCommandOutput(script: """
                    cd "${projectDir}"
                    if [ -d "${moduleName}" ]; then
                        cd "${moduleName}"
                        pwd
                    fi
                """)
                if (moduleDir && pomByDir.containsKey(moduleDir)) {
                    moduleDirs << moduleDir
                }
            }
        }
    }

    return pomByDir.keySet().findAll { !moduleDirs.contains(it) }.sort()
}

def prepareDockerProjectEntries(def globals, def cacheContext, def sourceDirs, def excludedDirs, def defaultSbomName) {
    def mavenContextRoot = "${cacheContext.dir}/maven-contexts"
    def mavenProjectDirs = findMavenProjectDirs(sourceDirs, excludedDirs)

    return mavenProjectDirs.withIndex().collect { projectDir, index ->
        def projectId = makeProjectId(globals, projectDir, index)
        def contextDir = "${mavenContextRoot}/${projectId}"
        sh """
            set -e
            rm -rf "${contextDir}"
            mkdir -p "${contextDir}"
            cd "${projectDir}"

            find . \\( -path './target' -o -path './target/*' -o -path './build' -o -path './build/*' \\) -prune -o \\
                -name 'pom.xml' -type f -print | while IFS= read -r file_path; do
                    dest="${contextDir}/\${file_path#./}"
                    mkdir -p "\$(dirname "\$dest")"
                    cp "\$file_path" "\$dest"
                done

            if [ -d .mvn ]; then
                mkdir -p "${contextDir}/.mvn"
                cp -R .mvn/. "${contextDir}/.mvn"/
            fi
        """
        return [
            type: "maven",
            projectDir: projectDir,
            contextDir: contextDir,
            sbomPath: "${projectDir}/${defaultSbomName}",
            keyInfo: [projectId: projectId],
            cacheMounts: [[id: "sbom-maven-${projectId}", target: "/root/.m2"]]
        ]
    }
}

def findSbomMergePaths(def extension, def defaultSbomName, def globals) {
    def configDir = env.CONFIG_DIR ?: ""
    def sbomMergePaths = extension.sbom_merge_paths ?: []
    if (sbomMergePaths instanceof String) sbomMergePaths = [sbomMergePaths.trim()]

    if (sbomMergePaths.any { it == "" }) {
        unstable "Параметр sbom_merge_paths содержит недопустимое значение. " +
            "Для объединения пользовательских SBOM файлов со сгенерированным " +
            "SBOM ${defaultSbomName} укажите в параметре sbom_merge_paths имя SBOM файлов"
    }

    def paths = [
        exists: [] as Set,
        notExists: [] as Set
    ]

    sbomMergePaths.each { path ->
        dir(env.WORKSPACE) {
            def absolutePaths = findFiles(glob: path)
            if (absolutePaths == null || absolutePaths.length == 0) {
                paths.notExists << path
            } else {
                absolutePaths.each { extractedPath ->
                    paths.exists << extractedPath.path
                }
            }
        }
    }

    if (extension.sbom_merge_paths == null) {
        def defaultCustomSbomPath = "${globals.DIR_TMP_CONFIG}/${configDir}/additional_sbom.json"
        if (!fileExists(defaultCustomSbomPath)) {
            echo("SBOM файл additional_sbom.json в корне репозитория с конфигурацией проекта " +
                "для объединения со сгенерированным SBOM ${defaultSbomName} не найден")
        } else {
            paths.exists << defaultCustomSbomPath
        }
    }

    return paths
}

def normalizeCacheConfig(def extension) {
    def cache = extension.cache
    if (cache == null || cache == false) return null

    if (!(cache instanceof Map)) {
        unstable("Параметр cache должен быть map с scanned_image_cache для Docker cache. " +
            "Кеширование SBOM будет отключено.")
        return null
    }

    def scannedImageCache = cache.scanned_image_cache?.toString()?.trim()
    def scannerImage = "ghcr.io/cyclonedx/cdxgen:v12"
    scannerImage = cache.scanner_image?.toString()?.trim() ?: cache.scanner?.toString()?.trim() ?: scannerImage
    def builder = cache.builder?.toString()?.trim() ?: "buildx"

    builder = builder.toLowerCase()
    if (!(builder in ["buildx", "buildctl"])) {
        unstable("Параметр cache.builder=${builder} не поддерживается. Будет использован buildx.")
        builder = "buildx"
    }

    if (!scannedImageCache) {
        unstable("Параметр cache должен содержать scanned_image_cache для Docker registry cache. " +
            "Кеширование SBOM будет отключено.")
        return null
    }

    return [
        backend: "docker",
        registryRef: scannedImageCache,
        scannerImage: scannerImage,
        builder: builder
    ]
}

def prepareDockerBuildContext(def cacheConfig, def globals) {
    def cacheDir = "${globals.DIR_TMP}/generateSBOMCyclonedx-docker-cache"
    def builderName = "sbom-cdxgen-${UUID.randomUUID().toString()}"
    def buildkitConfigPath = "${cacheDir}/buildkitd.toml"

    sh """
        set -e
        rm -rf "${cacheDir}"
        mkdir -p "${cacheDir}"
    """

    if (cacheConfig.builder == "buildctl") {
        sh """
            set -e
            buildctl --version >/dev/null
        """

        echo("SBOM Docker build подготовлен: registry cache ${cacheConfig.registryRef}, scanner image ${cacheConfig.scannerImage}, builder buildctl. " +
            "Ограничение параллелизма для buildctl настраивается на внешнем buildkitd.")
        return [
            backend: "docker",
            dir: cacheDir,
            registryRef: cacheConfig.registryRef,
            scannerImage: cacheConfig.scannerImage,
            builder: "buildctl"
        ]
    }

    sh """
        set -e
        docker buildx version >/dev/null
    """

    writeFile file: buildkitConfigPath, text: """[worker.oci]
  max-parallelism = 4
"""

    sh """
        set -e
        docker buildx create \
            --name "${builderName}" \
            --driver docker-container \
            --config "${buildkitConfigPath}" >/dev/null
        docker buildx inspect "${builderName}" --bootstrap >/dev/null
    """

    echo("SBOM Docker build подготовлен: registry cache ${cacheConfig.registryRef}, scanner image ${cacheConfig.scannerImage}, builder ${builderName}")
    return [
        backend: "docker",
        dir: cacheDir,
        registryRef: cacheConfig.registryRef,
        scannerImage: cacheConfig.scannerImage,
        builder: "buildx",
        builderName: builderName,
        buildkitConfigPath: buildkitConfigPath
    ]
}

def createCacheContext(def extension, def globals) {
    def cacheConfig = normalizeCacheConfig(extension)
    if (!cacheConfig) return null

    try {
        return prepareDockerBuildContext(cacheConfig, globals)
    } catch (err) {
        def cacheDescription = "Docker cache ${cacheConfig.registryRef}"
        unstable("Не удалось подготовить ${cacheDescription}. " +
            "Сканирование будет выполнено без кеша. Ошибка: ${err}")
        return null
    }
}

def getCommandOutput(def args) {
    def script = args instanceof Map ? args.script : args
    return sh(script: script, returnStdout: true).trim()
}

def getCdxgenVersion(def cdxgenPath) {
    return getCommandOutput(script: """
        set +e
        \${CYCLONE}/${cdxgenPath} --version 2>&1 || true
    """)
}

def makeProjectId(def globals, def projectDir, def index = 0) {
    def projectName = projectDir
    if (projectDir == globals.DIR_SRC) {
        projectName = "sources"
    } else if (projectDir.startsWith("${globals.DIR_SRC}/")) {
        projectName = projectDir.substring("${globals.DIR_SRC}/".length())
    } else if (projectDir.startsWith("${globals.DIR_TMP}/")) {
        projectName = projectDir.substring("${globals.DIR_TMP}/".length())
    } else {
        projectName = projectDir.tokenize('/').last() ?: "root"
    }

    projectName = projectName.replaceAll(/[^A-Za-z0-9_.-]/, "_")
    return "${index}_${projectName}"
}

void runDockerBatchWithBuildx(def cacheContext, def dockerfilePath, def outputDir, def entries, def envParamsPath, def mavenSettingsPath = null) {
    def secretArgs = []
    if (envParamsPath) {
        secretArgs << "--secret \"id=envParams,src=${envParamsPath}\""
    }
    if (mavenSettingsPath) {
        secretArgs << "--secret \"id=maven_settings,src=${mavenSettingsPath}\""
    }

    def contextArgs = entries.withIndex().collect { entry, index ->
        "--build-context project_${index}=\"${entry.contextDir}\""
    }
    def baseArgs = ([
        cacheContext.builderName ? "--builder \"${cacheContext.builderName}\"" : "",
        "--progress=plain"
    ] + contextArgs + [
        "--file \"${dockerfilePath}\"",
        "--target export",
        "--output \"type=local,dest=${outputDir}\"",
        secretArgs.join(" "),
        "\"${cacheContext.dir}\""
    ]).findAll { it }.join(" ")

    def cacheFromArg = cacheContext.registryRef ? "--cache-from \"type=registry,ref=${cacheContext.registryRef}\"" : ""
    def cacheToArg = cacheContext.registryRef ? "--cache-to \"type=registry,ref=${cacheContext.registryRef},mode=max\"" : ""

    sh """
        set -e
        docker buildx build ${cacheFromArg} ${cacheToArg} ${baseArgs}
    """
}

void runDockerBatchWithBuildctl(def cacheContext, def dockerfilePath, def outputDir, def entries, def envParamsPath, def mavenSettingsPath = null) {
    def dockerfileName = dockerfilePath.tokenize('/').last()
    def secretArgs = []
    if (envParamsPath) {
        secretArgs << "--secret \"id=envParams,src=${envParamsPath}\""
    }
    if (mavenSettingsPath) {
        secretArgs << "--secret \"id=maven_settings,src=${mavenSettingsPath}\""
    }

    def localArgs = ([
        "--local context=\"${cacheContext.dir}\"",
        "--local dockerfile=\"${cacheContext.dir}\""
    ] + entries.withIndex().collect { entry, index ->
        "--local project_${index}=\"${entry.contextDir}\""
    }).join(" ")
    def baseArgs = [
        "--progress=plain",
        "--frontend dockerfile.v0",
        localArgs,
        "--opt \"filename=${dockerfileName}\"",
        "--opt target=export",
        "--output \"type=local,dest=${outputDir}\"",
        secretArgs.join(" ")
    ].findAll { it }.join(" ")

    def cacheFromArg = cacheContext.registryRef ? "--import-cache \"type=registry,ref=${cacheContext.registryRef}\"" : ""
    def cacheToArg = cacheContext.registryRef ? "--export-cache \"type=registry,ref=${cacheContext.registryRef},mode=max\"" : ""

    sh """
        set -e
        buildctl build ${cacheFromArg} ${cacheToArg} ${baseArgs}
    """
}

def runCdxgenWithDockerCacheBatch(def cacheContext, def entries, def cdxgenArgs, def envParamsPath, def mavenSettingsPath = null) {
    if (!entries) return

    def batchId = UUID.randomUUID().toString()
    def dockerfilePath = "${cacheContext.dir}/Dockerfile.batch.${batchId}"
    def outputDir = "${cacheContext.dir}/output-batch-${batchId}"
    def secretMounts = envParamsPath ? "--mount=type=secret,id=envParams" : ""
    if (mavenSettingsPath) {
        secretMounts = [secretMounts, "--mount=type=secret,id=maven_settings"].findAll { it }.join(" ")
    }
    def envParamsExport = envParamsPath ? ". /run/secrets/envParams; " : ""
    def settingsExport = mavenSettingsPath ? 'export MVN_ARGS="${MVN_ARGS:-} -s /run/secrets/maven_settings"; ' : ""

    def stages = entries.withIndex().collect { entry, index ->
        def stageName = "scan${index}"
        def projectContext = "project_${index}"
        def args = cdxgenArgs.collect { it.toString() }
        def cdxgenCommand = "cdxgen -o /out/sbom.json ${args.join(' ')} ."
        def cacheMounts = (entry.cacheMounts ?: []).collect { cacheMount ->
            "--mount=type=cache,id=${cacheMount.id},target=${cacheMount.target},sharing=locked"
        }.join(" ")
        def runMounts = [cacheMounts, secretMounts].findAll { it }.join(" ")
        return """FROM ${cacheContext.scannerImage} AS ${stageName}
WORKDIR /workspace
COPY --from=${projectContext} / /workspace/
RUN ${runMounts ? runMounts + " " : ""}${envParamsExport}${settingsExport}mkdir -p /out && ${cdxgenCommand}
"""
    }.join("\n")
    def exports = entries.withIndex().collect { entry, index ->
        "COPY --from=scan${index} /out/sbom.json /${entry.keyInfo.projectId}/sbom.json"
    }.join("\n")
    def dockerfile = """# syntax=docker/dockerfile:1.7
${stages}
FROM scratch AS export
${exports}
"""

    writeFile file: dockerfilePath, text: dockerfile
    echo("SBOM Docker scan: projects=${entries.size()}, builder=${cacheContext.builder}, " +
        "scanner=${cacheContext.scannerImage}")

    sh """
        set -e
        rm -rf "${outputDir}"
    """
    if (cacheContext.builder == "buildctl") {
        runDockerBatchWithBuildctl(cacheContext, dockerfilePath, outputDir, entries, envParamsPath, mavenSettingsPath)
    } else {
        runDockerBatchWithBuildx(cacheContext, dockerfilePath, outputDir, entries, envParamsPath, mavenSettingsPath)
    }

    def successCount = 0
    entries.each { entry ->
        def exportedSbomPath = "${outputDir}/${entry.keyInfo.projectId}/sbom.json"
        sh """
            set -e
            cp "${exportedSbomPath}" "${entry.sbomPath}"
        """
        successCount++
    }

    echo("SBOM сгенерирован через Docker cache ${cacheContext.registryRef}: ${successCount}/${entries.size()} проектов")
}

void run(def extension, def extensionAPI) {
    def distrib = extensionAPI.distrib
    def globals = distrib.globals
    def config = extensionAPI.getPipelineConfig()
    def defaultSbomName = "sbom.json"
    def specVersion = extension.spec_version ?: "v1_6"
    def args = extension.args instanceof String ? [extension.args] : (extension.args ?: [])
    def sbomNames = extension.sbom_paths ?: [defaultSbomName]
    def sbomTemplatePath = "${globals.DIR_SRC}/sbomTemplate.json"
    def cdxgenPath = extension.cdxgen_path ?: "cdxgen-linux-x64"
    def tools = getTools(extension)
    def envs = getEnvs(extension)
    def mavenSettingsId = getMavenSettingsId(config, extension)
    def gavtc = distrib.gavtc.clone()
    def cyclonedxCliPath = extension.cyclonedx_cli_path ?: "cyclonedx-linux-x64"
    def sbomMergePaths = findSbomMergePaths(extension, defaultSbomName, globals)
    
    gavtc.type = 'json'
    gavtc.classifier = extension.classifier ?: "cyclonedx-distrib"
    if (extension.version) gavtc.version = extension.version

    generateSBOMTemplate(sbomTemplatePath, gavtc, config.fp.component_code)

    def runner = {
        def excludedSbomMap = [:]
        def cdxgenArgs = args.collect { it }

        withEnv(tools + envs) {
            def useNewVersion = isNewVersion(cdxgenPath)
            def sourceDirs = getSourceDirs(globals)
            def scannedSbomPaths = []
            def cacheContext = createCacheContext(extension, globals)
            def mavenSettingsPath = env.MAVEN_SETTINGS_FILE ?: null
            def dockerEnvParamsPath = cacheContext ? getDockerEnvAssignments(globals, envs) : null

            if (useNewVersion) {
                excludedSbomMap = getExcluded(sourceDirs, sbomNames)
                scannedSbomPaths = excludedSbomMap.collect { _, fullPath -> fullPath }
                def excludePatterns = excludedSbomMap.collect { dir, _ -> "\"${dir}/**\"" }

                excludePatterns.each { pattern ->
                    cdxgenArgs.add("--exclude")
                    cdxgenArgs.add(pattern)
                }

                cdxgenArgs.add("--exclude")
                cdxgenArgs.add("\"**/.m2/**\"")
            }

            def excludedDirs = excludedSbomMap.keySet() as List
            def dockerProjectEntries = []
            def dockerProjectDirs = []
            def hostExcludedDirs = excludedDirs
            def hostCdxgenArgs = cdxgenArgs

            if (cacheContext) {
                dockerProjectEntries = prepareDockerProjectEntries(globals, cacheContext, sourceDirs, excludedDirs, defaultSbomName)
                dockerProjectDirs = dockerProjectEntries.collect { it.projectDir }
                hostExcludedDirs = excludedDirs + dockerProjectDirs

                def dockerExcludeArgs = dockerProjectDirs.collectMany { dockerProjectDir ->
                    ["--exclude", "\"${dockerProjectDir}/**\""]
                }
                hostCdxgenArgs = cdxgenArgs + dockerExcludeArgs
            }

            def projectDirs = getProjectDirs(globals, useNewVersion, sourceDirs, hostExcludedDirs)
            def hostProjectEntries = projectDirs.findAll { projectDir ->
                fileExists(projectDir)
            }.collect { projectDir ->
                [
                    projectDir: projectDir,
                    sbomPath: "${projectDir}/${defaultSbomName}",
                    keyInfo: null
                ]
            }

            if (cacheContext) {
                hostProjectEntries = hostProjectEntries.findAll { entry ->
                    !dockerProjectDirs.any { dockerProjectDir ->
                        entry.projectDir == dockerProjectDir || entry.projectDir.startsWith("${dockerProjectDir}/")
                    }
                }

                echo("SBOM Docker scan: найдено проектов для Docker scan ${dockerProjectEntries.size()}, " +
                    "обычных host проектов ${hostProjectEntries.size()}")
            }

            def projectEntries = dockerProjectEntries + hostProjectEntries

            if (cacheContext && dockerProjectEntries) {
                runCdxgenWithDockerCacheBatch(cacheContext, dockerProjectEntries, cdxgenArgs, dockerEnvParamsPath, mavenSettingsPath)
            }

            projectEntries.each { entry ->
                def projectDir = entry.projectDir
                def sbomPath = entry.sbomPath

                if (!(entry.keyInfo && fileExists(sbomPath))) {
                    def scanArgs = entry.keyInfo ? cdxgenArgs : hostCdxgenArgs
                    sh "\${CYCLONE}/${cdxgenPath} -r -o \"${sbomPath}\" ${scanArgs.join(' ')} \"${projectDir}\""
                }

                if (fileExists(sbomPath)) scannedSbomPaths << sbomPath
            }

            def allSboms = ([sbomTemplatePath] + sbomMergePaths.exists + scannedSbomPaths).unique()

            if (useNewVersion) {
                allSboms = (allSboms + excludedSbomMap.values()).unique()
            }

            def mergedPath = "${globals.DIR_SRC}/${defaultSbomName}"
            sh """
                \${CYClONE_CLI}/${cyclonedxCliPath} merge \
                    --input-files ${allSboms.join(' ')} \
                    --output-file ${mergedPath}
                \${CYClONE_CLI}/${cyclonedxCliPath} convert \
                    --output-version ${specVersion} \
                    --input-file ${mergedPath} \
                    --output-file ${mergedPath}
            """

            echo("Следующие SBOM файлы ${allSboms.join(' ')} успешно объединены со сгенерированным SBOM ${mergedPath}")
            if (sbomMergePaths.notExists) {
                unstable("Следующие SBOM файлы ${sbomMergePaths.notExists.join(' ')} " + 
                    "не найдены. Проверьте корректность заполнения параметра sbom_merge_paths")
            }

            extensionAPI.pipelineConfig.distribution?.findAll {
                it.type == "maven" || !it.type 
            }.each {
                it.classifiers = it.classifiers ?: [:]
                it.classifiers[gavtc.classifier] = [
                    file: mergedPath,
                    type: gavtc.type
                ]
            }
        }
    }
    runner = wrapMavenSettingsFile(mavenSettingsId, runner)
    runner = wrapNodejs(config, extension, runner)
    runner = wrapMaven(config, extension, runner)
    runner()
}

def isNewVersion(def cdxgenPath) {
    def versionOutput = sh(
            script: "\\${CYCLONE}/${cdxgenPath} --version",
            returnStdout: true
    ).trim()

    def matcher = versionOutput =~ /(\d+\.\d+\.\d+)/
    if (!matcher.find()) return false

    def current = matcher.group(1).tokenize('.').collect { it as int }
    def required = [9, 9, 3]

    for (int i = 0; i < 3; i++) {
        int a = (i < current.size()) ? current[i] : 0
        int b = required[i]
        if (a > b) return true
        if (a < b) return false
    }

    return true
}

return this
