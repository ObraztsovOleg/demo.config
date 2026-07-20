def getDefaultConfig() {
    return [
            stage      : "pack",
            phase      : "before",
            description: "Анализ зависимостей сборочных проектов"
    ]
}

def normalizeList(def value) {
    if (value == null) return []
    if (value instanceof List) return value
    if (value instanceof String) return value.trim() ? [value.trim()] : []
    return [value]
}

def sha256Text(def value) {
    def digest = java.security.MessageDigest.getInstance("SHA-256")
        .digest(value.toString().getBytes("UTF-8"))
    return digest.collect { String.format("%02x", ((int) it) & 0xff) }.join("")
}

def envAssignmentsToMap(def value) {
    def result = [:]
    if (!value) return result

    if (value instanceof Map) {
        value.each { key, envValue ->
            if (key != null && envValue != null) result[key.toString()] = envValue.toString()
        }
        return result
    }

    normalizeList(value).each { item ->
        if (item instanceof Map) {
            item.each { key, envValue ->
                if (key != null && envValue != null) result[key.toString()] = envValue.toString()
            }
        } else {
            def text = item.toString()
            def separatorIndex = text.indexOf("=")
            if (separatorIndex > 0) {
                result[text.substring(0, separatorIndex)] = text.substring(separatorIndex + 1)
            }
        }
    }

    return result
}

def envMapToAssignments(def envMap) {
    if (!envMap) return []
    return envMap.collect { key, value -> "${key}=${value}" }
}

def getPathTail(def path) {
    return path?.toString()?.tokenize('/')?.last() ?: ""
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
    if (config.maven || extension.maven) {
        result = {
            def envEntries = []
            if (mavenHome) {
                def mavenTool = tool name: mavenHome
                envEntries << "PATH+MAVEN=${mavenTool}/bin"
            }
            if (jdk) {
                def jdkTool = tool name: jdk
                envEntries << "JAVA_HOME=${jdkTool}"
                envEntries << "PATH+JDK=${jdkTool}/bin"
            }
            withEnv(envEntries) {
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

def getMavenSettingsId(def config, def extension) {
    return extension.maven?.settings_id ?: config.maven?.settings_id
}

def isExcludedDir(def path, def excludedDirs) {
    return normalizeList(excludedDirs).any { excluded ->
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

def getGeneratedAnalysisDir(def projectDir, def name) {
    return "${projectDir}/.sbom-cyclonedx/${name}"
}

def createSDKPomsFolder(def projectDirs, def excludedDirs = []) {
    def generatedDirs = []

    projectDirs.findAll { fileExists(it) && !isExcludedDir(it, excludedDirs) }.each { projectDir ->
        def pomsDir = getGeneratedAnalysisDir(projectDir, "poms")
        def generatedRoot = "${projectDir}/.sbom-cyclonedx"
        def prune = findPruneExpression((normalizeList(excludedDirs) + [generatedRoot]).unique())
        def pomPaths = sh(
            script: "find \"${projectDir}\" ${prune} -name '*.pom' -type f -print",
            returnStdout: true
        ).tokenize("\n")

        if (pomPaths) {
            def poms = getPoms(pomPaths)
            def paths = createPaths(poms)

            sh "mkdir -p \"${pomsDir}\""
            dir(pomsDir) {
                createPomHirarchy(paths)
            }
            generatedDirs << pomsDir
        }
    }

    return generatedDirs
}

void createPomHirarchy(def paths) {
    paths.each { info ->
        dir(info.dest) {
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

def extractTgz(def projectDirs, def excludedDirs = []) {
    def generatedDirs = []

    projectDirs.findAll { fileExists(it) && !isExcludedDir(it, excludedDirs) }.each { projectDir ->
        def tgzDir = getGeneratedAnalysisDir(projectDir, "tgz")
        def generatedRoot = "${projectDir}/.sbom-cyclonedx"
        def prune = findPruneExpression((normalizeList(excludedDirs) + [generatedRoot]).unique())
        def tgzPaths = sh(
            script: "find \"${projectDir}\" ${prune} \\( -name '*.tgz' -o -name '*.tgz.gz' \\) -type f -print",
            returnStdout: true
        ).tokenize("\n")

        tgzPaths.each { tgzPath ->
            def objectFilePath = "${tgzDir}/${sha256Text(tgzPath).take(16)}"
            sh """
                mkdir -p "${objectFilePath}"
                tar -xvzf "${tgzPath}" -C "${objectFilePath}"
            """
        }

        if (tgzPaths) {
            generatedDirs << tgzDir
        }
    }

    return generatedDirs
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
    def projectRoots = activeSourceDirs ? activeSourceDirs.collect { it } : [globals.DIR_SRC]
    if (fileExists(globals.DIR_SDK) && !isExcludedDir(globals.DIR_SDK, excludedDirs)) {
        projectRoots << globals.DIR_SDK
    }
    projectRoots = projectRoots.unique()
    def generatedAnalysisDirs = createSDKPomsFolder(projectRoots, excludedDirs) +
        extractTgz(projectRoots, excludedDirs)

    def analysisDirs = []
    if (!useNewVersion) {
        analysisDirs += getGradlePaths(globals, excludedDirs)
    }
    analysisDirs += generatedAnalysisDirs

    def projectDirs = projectRoots + analysisDirs
    return projectDirs.flatten().unique()
}

def getExcluded(def globals, def sbomPaths) {
    def srcDirs = getSourceDirs(globals)
    def scannedReposWithReportPaths = [:]

    srcDirs.each { directory ->
        def allFound = []

        sbomPaths.each { sbomPath ->
            def sbomAntName = sbomPath.startsWith(directory) ? sbomPath.minus(directory) : sbomPath
            def sbomFiles = sh(
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
        "CYCLONE=${tool name: extension.cdxgen ?: 'cdxgen-8.6.2'}",
        "CYClONE_CLI=${tool name: extension.cyclonedx_cli ?: 'cyclonedx-linux-x64-v0.27.1'}",
        "MVN_ARGS=${env.MVN_ARGS ?: '-DincludeProvidedScope=false'}",
        "CDX_MAVEN_INCLUDE_TEST_SCOPE=${env.CDX_MAVEN_INCLUDE_TEST_SCOPE ?: false}",
        "NODE_EXTRA_CA_CERTS=${env.NODE_EXTRA_CA_CERTS ?: env.TRUSTED_CERT_CHAIN_PATH ?: ''}"
    ]
    normalizeList(extension.tools).each { toolName ->
        def toolPath = tool name: toolName
        if (fileExists("$toolPath/bin")) toolPath = "$toolPath/bin"

        tools += "PATH+TOOL_PATH=$toolPath"
    }

    return tools
}

def getEnvs(def extension) {
    return envMapToAssignments(envAssignmentsToMap(extension.env))
}

def getScanBaseEnvMap(def tools, def envs) {
    def result = envAssignmentsToMap(normalizeList(tools) + normalizeList(envs))
    return result.findAll { key, _ ->
        def keyText = key.toString()
        !(keyText.startsWith("PATH+")) && !(keyText in ["CYCLONE", "CYClONE_CLI"])
    }
}

def getGradlePaths(def globals, def excludedDirs = []) {
    def prune = findPruneExpression(excludedDirs)
    return sh(
        script: "find ${globals.DIR_SRC} ${prune} -name build.gradle -printf '%h\n'",
        returnStdout: true
    ).tokenize("\n")
}

def getSourceDirs(def globals) {
    if (!fileExists(globals.DIR_SRC)) return []

    return sh(
        script: "find ${globals.DIR_SRC} -maxdepth 1 -type d -not -path '${globals.DIR_SRC}' -not -empty",
        returnStdout: true
    ).tokenize("\n")
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

def normalizeCacheConfigs(def cache, def label = "cache") {
    def cacheItems
    if (cache == null) {
        cacheItems = []
    } else if (cache instanceof List) {
        cacheItems = cache
    } else if (cache instanceof Map) {
        cacheItems = [cache]
    } else {
        cacheItems = []
    }

    return cacheItems.collect { item ->
        if (!(item instanceof Map)) return null

        def type = item.type?.toString()?.trim()?.toLowerCase() ?: "nexus"
        if (type != "nexus") return null

        def url = item.url?.toString()?.trim()
        if (!url) {
            unstable("Параметр ${label} type=nexus должен содержать url. Cache backend будет проигнорирован.")
            return null
        }

        return [
            backend: "nexus",
            url: trimSlashes(url, false, true),
            creds: item.creds?.toString()?.trim(),
            prefix: trimSlashes(item.prefix?.toString()?.trim() ?: "sbom-cache/v1", true, true)
        ]
    }.findAll { it }
}

def trimSlashes(def value, boolean leading, boolean trailing) {
    def result = value?.toString() ?: ""
    if (leading) result = result.replaceFirst(/^\/+/, "")
    if (trailing) result = result.replaceFirst(/\/+$/, "")
    return result
}

def cacheConfigKey(def cacheConfig) {
    if (!cacheConfig) return "none"
    return sha256Text(cacheConfig.collect { key, value -> "${key}=${value}" }.sort().join("\n"))
}

def getProjectSourceName(def globals, def projectDir) {
    if (projectDir?.startsWith("${globals.DIR_SRC}/")) {
        return projectDir.substring("${globals.DIR_SRC}/".length()).tokenize('/').first()
    }

    return getPathTail(projectDir)
}

def getSourceOverrides(def extension) {
    def sources = extension.sources
    if (!sources) return []

    def sourceItems = sources instanceof List ? sources : [sources]
    return sourceItems.collect { source ->
        if (!(source instanceof Map)) {
            unstable("Параметр sources должен быть list of maps. Элемент ${source} будет проигнорирован.")
            return null
        }

        def name = source.name?.toString()?.trim()
        if (!name) {
            unstable("Параметр sources[].name обязателен. Элемент sources будет проигнорирован.")
            return null
        }

        return [
            name: name,
            args: normalizeList(source.args),
            env: envAssignmentsToMap(source.env),
            tools: normalizeList(source.tools),
            hasCache: source.containsKey("cache"),
            cacheConfigs: source.containsKey("cache") ?
                normalizeCacheConfigs(source.cache, "sources.${name}.cache") :
                null
        ]
    }.findAll { it }
}

def findSourceOverride(def globals, def sourceOverrides, def projectDir) {
    if (!sourceOverrides) return null

    def projectPath = projectDir.toString()
    def relativePath = projectPath.startsWith("${globals.DIR_SRC}/") ?
        projectPath.substring("${globals.DIR_SRC}/".length()) :
        projectPath
    def candidates = [
        projectPath,
        relativePath,
        getPathTail(projectPath),
        getProjectSourceName(globals, projectPath)
    ].findAll { it }.unique()

    return sourceOverrides.find { source ->
        def sourceName = source.name.toString()
        candidates.contains(sourceName) || projectPath.endsWith("/${sourceName}") || projectPath.contains("/${sourceName}/")
    }
}

def getSourceToolEnvs(def sourceOverride) {
    def result = []
    normalizeList(sourceOverride?.tools).eachWithIndex { toolName, index ->
        def toolPath = tool name: toolName.toString()
        if (fileExists("${toolPath}/bin")) toolPath = "${toolPath}/bin"
        result << "PATH+SOURCE_TOOL_${index}_PATH=${toolPath}"
    }
    return result
}

def getEffectiveCacheConfig(def sourceOverride, def globalCacheConfigs) {
    def cacheConfigs = sourceOverride?.hasCache ? sourceOverride.cacheConfigs : globalCacheConfigs
    return normalizeList(cacheConfigs).find { it }
}

def getScanConfig(def globals, def sourceOverrides, def globalCacheConfigs, def baseArgs, def baseEnvMap, def projectDir) {
    def sourceOverride = findSourceOverride(globals, sourceOverrides, projectDir)
    return [
        args: normalizeList(baseArgs) + normalizeList(sourceOverride?.args),
        env: [:] + baseEnvMap + (sourceOverride?.env ?: [:]),
        tools: getSourceToolEnvs(sourceOverride),
        cacheConfig: getEffectiveCacheConfig(sourceOverride, globalCacheConfigs)
    ]
}

def getScanTypeInfo(def args) {
    def tokens = normalizeList(args)
    def scanTypes = []
    def cleanedArgs = []

    for (int index = 0; index < tokens.size(); index++) {
        def token = tokens[index].toString()
        if (token == "-t" || token == "--type") {
            if (index + 1 < tokens.size()) {
                scanTypes += tokens[index + 1].toString().split(",").collect { it.trim().toLowerCase() }.findAll { it }
            }
            index++
        } else if (token.startsWith("--type=")) {
            scanTypes += token.substring("--type=".length()).split(",").collect { it.trim().toLowerCase() }.findAll { it }
        } else {
            cleanedArgs << tokens[index]
        }
    }

    scanTypes = scanTypes.unique()
    def binaryTypes = scanTypes.findAll { it == "jar" }
    def cacheableTypes = scanTypes.findAll { !(it in binaryTypes) }

    return [
        scanTypes: scanTypes,
        binaryTypes: binaryTypes,
        cacheableTypes: cacheableTypes,
        cleanedArgs: cleanedArgs
    ]
}

def withCdxgenTypes(def cleanedArgs, def scanTypes) {
    def result = normalizeList(cleanedArgs).collect { it }
    normalizeList(scanTypes).each { scanType ->
        result += ["-t", scanType.toString()]
    }
    return result
}

def makeProjectId(def globals, def projectDir, def suffix = null) {
    def projectName = projectDir
    if (projectDir == globals.DIR_SRC) {
        projectName = "sources"
    } else if (projectDir.startsWith("${globals.DIR_SRC}/")) {
        projectName = projectDir.substring("${globals.DIR_SRC}/".length())
    } else if (projectDir.startsWith("${globals.DIR_TMP}/")) {
        projectName = projectDir.substring("${globals.DIR_TMP}/".length())
    } else {
        projectName = getPathTail(projectDir) ?: "root"
    }

    projectName = projectName.replaceAll(/[^A-Za-z0-9_.-]/, "_")
    return suffix ? "${projectName}_${suffix}" : projectName
}

def createScanEntries(def globals, def projectDir, def defaultSbomName, def scanConfig) {
    def typeInfo = getScanTypeInfo(scanConfig.args)
    def projectId = makeProjectId(globals, projectDir)
    def entries = []

    if (typeInfo.binaryTypes && (typeInfo.cacheableTypes || !typeInfo.scanTypes)) {
        entries << [
            type: "manifest",
            projectDir: projectDir,
            sbomPath: "${projectDir}/${defaultSbomName}",
            projectId: projectId,
            cdxgenArgs: typeInfo.cacheableTypes ?
                withCdxgenTypes(typeInfo.cleanedArgs, typeInfo.cacheableTypes) :
                normalizeList(scanConfig.args),
            effectiveEnv: scanConfig.env,
            sourceTools: scanConfig.tools,
            cacheConfig: scanConfig.cacheConfig
        ]
    } else if (!typeInfo.binaryTypes) {
        entries << [
            type: "manifest",
            projectDir: projectDir,
            sbomPath: "${projectDir}/${defaultSbomName}",
            projectId: projectId,
            cdxgenArgs: normalizeList(scanConfig.args),
            effectiveEnv: scanConfig.env,
            sourceTools: scanConfig.tools,
            cacheConfig: scanConfig.cacheConfig
        ]
    }

    if (typeInfo.binaryTypes) {
        entries << [
            type: "artifact",
            artifactScan: true,
            projectDir: projectDir,
            sbomPath: "${globals.DIR_TMP}/${makeProjectId(globals, projectDir, 'artifact')}.sbom.json",
            projectId: makeProjectId(globals, projectDir, "artifact"),
            cdxgenArgs: withCdxgenTypes(typeInfo.cleanedArgs, typeInfo.binaryTypes),
            effectiveEnv: scanConfig.env,
            sourceTools: scanConfig.tools,
            cacheConfig: null
        ]
    }

    return entries
}

def getEntryLogLabel(def entry) {
    return "project=${getPathTail(entry.projectDir)}, type=${entry.type}, id=${entry.projectId}, key=${entry.cacheKey ?: '-'}"
}

def getCacheMaterial(def entry) {
    if (!entry?.projectDir || !fileExists(entry.projectDir)) return ""

    def filePatterns = [
        "pom.xml", "*.pom",
        "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradle.lockfile",
        "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
        "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock", "pyproject.toml",
        "go.mod", "go.sum",
        "Cargo.toml", "Cargo.lock",
        "composer.json", "composer.lock",
        "Gemfile", "Gemfile.lock",
        "*.csproj", "*.fsproj", "*.vbproj", "packages.lock.json"
    ]
    def ignoredDirs = [".git", ".m2", "target", "build", ".gradle", "node_modules"] as Set
    if (!entry.projectDir.contains("/.sbom-cyclonedx/")) {
        ignoredDirs << ".sbom-cyclonedx"
    }
    def files = [:]

    dir(entry.projectDir) {
        filePatterns.each { pattern ->
            findFiles(glob: "**/${pattern}").each { file ->
                def path = file.path.toString()
                def ignored = path.tokenize('/').any { ignoredDirs.contains(it) }
                if (!file.directory && !ignored) {
                    files[path] = sha256Text(readFile(file: path))
                }
            }
        }
    }

    return files.keySet().sort().collect { path ->
        "${path}\t${files[path]}"
    }.join("\n")
}

def getEntryEnvMaterial(def entry) {
    def envMap = (entry.effectiveEnv ?: [:]).findAll { key, _ ->
        def keyText = key.toString()
        !(keyText.startsWith("PATH+")) && !(keyText in ["CYCLONE", "CYClONE_CLI"])
    }
    return envMapToAssignments(envMap).sort().join("\n")
}

def prepareCacheKey(def entry, def cdxgenVersion, def mavenSettingsId) {
    if (entry.artifactScan) {
        entry.cacheStatus = "skip"
        echo("SBOM cache SKIP: backend=nexus, ${getEntryLogLabel(entry)}, reason=artifact scan is not cacheable")
        return false
    }
    if (!entry.cacheConfig) {
        entry.cacheStatus = "skip"
        return false
    }

    def material = getCacheMaterial(entry)
    if (!material) {
        entry.cacheStatus = "skip"
        echo("SBOM cache SKIP: backend=${entry.cacheConfig.backend}, ${getEntryLogLabel(entry)}, reason=no stable material")
        return false
    }

    entry.cacheKey = sha256Text([
        "project=${entry.projectId}",
        "args=${normalizeList(entry.cdxgenArgs).join('\n')}",
        "env=${getEntryEnvMaterial(entry)}",
        "cdxgenVersion=${cdxgenVersion ?: ''}",
        "settingsId=${mavenSettingsId ?: ''}",
        material
    ].join("\n"))
    return true
}

def getCacheObjectUrl(def cacheConfig, def entry) {
    if (!cacheConfig || !entry.cacheKey) return null
    def cacheFilePrefix = cacheConfig.prefix.toString().tokenize("/").join("-")
    return "${cacheConfig.url}/${cacheConfig.prefix}/${cacheFilePrefix}-${entry.cacheKey}.json"
}

def prepareCacheContext(def globals, def cacheConfig) {
    if (!cacheConfig) return null

    def cacheDir = "${globals.DIR_TMP}/generateSBOMCyclonedx-cache-${cacheConfigKey(cacheConfig).take(12)}"
    sh "mkdir -p \"${cacheDir}\""
    return cacheConfig + [dir: cacheDir]
}

def runCacheGet(def cacheContext, def url, def outputPath) {
    def curlScript = { authArg ->
        return """
            set +e
            http_code=\$(curl -k -sS ${authArg} -w "%{http_code}" -o "${outputPath}" "${url}" 2>"${outputPath}.err")
            curl_status=\$?
            echo "\${curl_status}:\${http_code}"
        """
    }

    if (!cacheContext?.creds) {
        return sh(script: curlScript(""), returnStdout: true)?.trim()
    }

    def response = null
    withCredentials([usernamePassword(
        credentialsId: cacheContext.creds,
        usernameVariable: "SBOM_CACHE_USERNAME",
        passwordVariable: "SBOM_CACHE_PASSWORD"
    )]) {
        response = sh(script: curlScript('-u "$SBOM_CACHE_USERNAME:$SBOM_CACHE_PASSWORD"'), returnStdout: true)
    }
    return response?.trim()
}

def runCachePut(def cacheContext, def url, def sourcePath, def outputPath) {
    def curlScript = { authArg ->
        return """
            set +e
            http_code=\$(curl -k -sS ${authArg} -X PUT --data-binary @"${sourcePath}" -w "%{http_code}" -o "${outputPath}" "${url}" 2>"${outputPath}.err")
            curl_status=\$?
            echo "\${curl_status}:\${http_code}"
        """
    }

    if (!cacheContext?.creds) {
        return sh(script: curlScript(""), returnStdout: true)?.trim()
    }

    def response = null
    withCredentials([usernamePassword(
        credentialsId: cacheContext.creds,
        usernameVariable: "SBOM_CACHE_USERNAME",
        passwordVariable: "SBOM_CACHE_PASSWORD"
    )]) {
        response = sh(script: curlScript('-u "$SBOM_CACHE_USERNAME:$SBOM_CACHE_PASSWORD"'), returnStdout: true)
    }
    return response?.trim()
}

def parseCacheResponse(def text) {
    if (!text) {
        return [
            curlStatus: 1,
            httpCode: 0
        ]
    }

    def parts = text.toString().trim().tokenize(":")
    return [
        curlStatus: parts ? parts.first().toInteger() : 1,
        httpCode: parts.size() > 1 ? parts.last().toInteger() : 0
    ]
}

void copyTextFile(def sourcePath, def targetPath) {
    def slashIndex = targetPath.lastIndexOf("/")
    if (slashIndex > 0) {
        def targetDir = targetPath.substring(0, slashIndex)
        def targetName = targetPath.substring(slashIndex + 1)
        sh "mkdir -p \"${targetDir}\""
        dir(targetDir) {
            writeFile file: targetName, text: readFile(file: sourcePath)
        }
        return
    }
    writeFile file: targetPath, text: readFile(file: sourcePath)
}

def isNonEmptySbom(def sbomPath) {
    if (!sbomPath || !fileExists(sbomPath)) return false

    try {
        def bom = readJSON(file: sbomPath)
        return normalizeList(bom.components).size() > 0
    } catch (err) {
        echo("SBOM cache: файл ${sbomPath} не удалось прочитать как CycloneDX JSON: ${err}")
        return false
    }
}

def restoreFromCache(def cacheContext, def entry) {
    def url = getCacheObjectUrl(cacheContext, entry)
    if (!url) return false

    def outputPath = "${cacheContext.dir}/${entry.projectId}-${entry.cacheKey}.json"
    def response = parseCacheResponse(runCacheGet(cacheContext, url, outputPath))

    if (response.curlStatus != 0) {
        entry.cacheStatus = "unavailable"
        unstable("SBOM cache UNAVAILABLE: backend=${cacheContext.backend}, ${getEntryLogLabel(entry)}, reason=curl failed")
        return false
    }
    if (response.httpCode == 404) {
        entry.cacheStatus = "miss"
        echo("SBOM cache MISS: backend=${cacheContext.backend}, ${getEntryLogLabel(entry)}, reason=not found")
        return false
    }
    if (response.httpCode != 200) {
        entry.cacheStatus = "unavailable"
        unstable("SBOM cache UNAVAILABLE: backend=${cacheContext.backend}, ${getEntryLogLabel(entry)}, http=${response.httpCode}")
        return false
    }
    if (!isNonEmptySbom(outputPath)) {
        entry.cacheStatus = "miss"
        echo("SBOM cache MISS: backend=${cacheContext.backend}, ${getEntryLogLabel(entry)}, reason=empty or invalid")
        return false
    }

    copyTextFile(outputPath, entry.sbomPath)
    entry.cacheStatus = "hit"
    echo("SBOM cache HIT: backend=${cacheContext.backend}, ${getEntryLogLabel(entry)}, action=restore and skip scan")
    return true
}

def saveToCache(def cacheContext, def entry) {
    if (!entry.cacheKey || entry.cacheStatus == "hit") {
        entry.cacheSaveStatus = "skip"
        return false
    }
    if (!isNonEmptySbom(entry.sbomPath)) {
        entry.cacheSaveStatus = "skip"
        echo("SBOM cache SAVE SKIP: backend=${cacheContext.backend}, ${getEntryLogLabel(entry)}, reason=sbom is empty or missing")
        return false
    }

    def url = getCacheObjectUrl(cacheContext, entry)
    def outputPath = "${cacheContext.dir}/${entry.projectId}-${entry.cacheKey}.put"
    def response = parseCacheResponse(runCachePut(cacheContext, url, entry.sbomPath, outputPath))

    if (response.curlStatus != 0 || !(response.httpCode in [200, 201, 204])) {
        entry.cacheSaveStatus = "failed"
        unstable("SBOM cache SAVE FAILED: backend=${cacheContext.backend}, ${getEntryLogLabel(entry)}, http=${response.httpCode}, curl=${response.curlStatus}")
        return false
    }

    entry.cacheSaveStatus = "saved"
    echo("SBOM cache SAVE: backend=${cacheContext.backend}, ${getEntryLogLabel(entry)}")
    return true
}

def getCdxgenVersion(def cdxgenPath) {
    return sh(script: "\${CYCLONE}/${cdxgenPath} --version 2>&1 || true", returnStdout: true).trim()
}

def scanEnvForEntry(def entry) {
    def result = normalizeList(entry.sourceTools) + envMapToAssignments(entry.effectiveEnv)
    if (env.MAVEN_SETTINGS_FILE) {
        def mvnArgs = entry.effectiveEnv?.MVN_ARGS ?: env.MVN_ARGS ?: ""
        if (!(mvnArgs ==~ /(?s).*(^|\s)(-s|--settings)(\s|=).*/)) {
            result << "MVN_ARGS=${[mvnArgs, "-s ${env.MAVEN_SETTINGS_FILE}"].findAll { it }.join(' ')}"
        }
    }
    return result
}

void runScan(def entry, def cdxgenPath, def extraExcludeDirs = []) {
    def scanArgs = normalizeList(entry.cdxgenArgs) + normalizeList(extraExcludeDirs).collectMany { dir ->
        ["--exclude", "\"${dir}/**\""]
    }
    entry.scanned = true
    echo("SBOM scan HOST: ${getEntryLogLabel(entry)}")
    withEnv(scanEnvForEntry(entry)) {
        sh "\${CYCLONE}/${cdxgenPath} -o \"${entry.sbomPath}\" ${scanArgs.join(' ')} \"${entry.projectDir}\""
    }
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
            def cdxgenVersion = getCdxgenVersion(cdxgenPath)
            def sourceDirs = getSourceDirs(globals)
            def sourceOverrides = getSourceOverrides(extension)
            def globalCacheConfigs = normalizeCacheConfigs(extension.cache)
            def baseEnvMap = getScanBaseEnvMap(tools, envs)
            def scannedSbomPaths = []

            if (useNewVersion) {
                excludedSbomMap = getExcluded(globals, sbomNames)
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
            def projectDirs = getProjectDirs(globals, useNewVersion, sourceDirs, excludedDirs)
            def cacheContexts = [:]
            def projectEntries = projectDirs.findAll { fileExists(it) }.collectMany { projectDir ->
                def scanConfig = getScanConfig(globals, sourceOverrides, globalCacheConfigs, cdxgenArgs, baseEnvMap, projectDir)
                createScanEntries(globals, projectDir, defaultSbomName, scanConfig)
            }

            projectEntries.each { entry ->
                if (entry.projectDir == globals.DIR_SRC) {
                    entry.cacheConfig = null
                }
                if (prepareCacheKey(entry, cdxgenVersion, mavenSettingsId)) {
                    def contextKey = cacheConfigKey(entry.cacheConfig)
                    cacheContexts[contextKey] = cacheContexts[contextKey] ?: prepareCacheContext(globals, entry.cacheConfig)
                    entry.cacheContext = cacheContexts[contextKey]
                    restoreFromCache(entry.cacheContext, entry)
                }
            }

            def cacheHitDirs = projectEntries.findAll { it.cacheStatus == "hit" && it.projectDir != globals.DIR_SRC }
                .collect { it.projectDir }
                .unique()

            def entriesToScan = projectEntries.findAll { entry ->
                !fileExists(entry.sbomPath) &&
                    (entry.artifactScan ||
                        !cacheHitDirs.any { hitDir -> entry.projectDir == hitDir || entry.projectDir.startsWith("${hitDir}/") })
            }

            entriesToScan.each { entry ->
                runScan(entry, cdxgenPath, cacheHitDirs)
            }

            projectEntries.findAll { it.cacheKey && it.cacheContext }.each { entry ->
                saveToCache(entry.cacheContext, entry)
            }

            projectEntries.each { entry ->
                if (fileExists(entry.sbomPath)) scannedSbomPaths << entry.sbomPath
            }

            def allSboms = ([sbomTemplatePath] + sbomMergePaths.exists + scannedSbomPaths).unique()

            if (useNewVersion) {
                allSboms = (allSboms + excludedSbomMap.values()).unique()
            }

            def cacheableEntries = projectEntries.findAll { it.cacheKey }
            def cacheHits = cacheableEntries.count { it.cacheStatus == "hit" }
            def cacheMisses = cacheableEntries.count { it.cacheStatus == "miss" }
            def cacheUnavailable = cacheableEntries.count { it.cacheStatus == "unavailable" }
            def cacheSaves = cacheableEntries.count { it.cacheSaveStatus == "saved" }
            def cacheSkips = projectEntries.count { it.cacheStatus == "skip" }
            def hostScans = projectEntries.count { it.scanned }
            echo("SBOM summary: cache hits=${cacheHits}, misses=${cacheMisses}, unavailable=${cacheUnavailable}, " +
                "skips=${cacheSkips}, saves=${cacheSaves}; Host scans=${hostScans}; merge files=${allSboms.size()}")

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

def versionAtLeast(def current, def required) {
    def result = (0..<required.size()).findResult { index ->
        int actual = index < current.size() ? current[index] : 0
        int expected = required[index]
        return actual == expected ? null : actual > expected
    }
    return result == null ? true : result
}

def isNewVersion(def cdxgenPath) {
    def versionOutput = sh(
            script: "\${CYCLONE}/${cdxgenPath} --version",
            returnStdout: true
    ).trim()

    def matcher = versionOutput =~ /(\d+\.\d+\.\d+)/
    if (!matcher.find()) return false

    def current = matcher.group(1).tokenize('.').collect { it as int }
    return versionAtLeast(current, [9, 9, 3])
}

return this
