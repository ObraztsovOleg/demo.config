// Метаданные расширения Jenkins: куда по умолчанию подключается шаг SBOM.
def getDefaultConfig() {
    return [
            stage      : "pack",
            phase      : "before",
            description: "Анализ зависимостей сборочных проектов"
    ]
}

// Приводит скалярное или списковое поле YAML к единому списку для дальнейшего объединения.
def normalizeList(def value) {
    if (value == null) return []
    if (value instanceof String) return value.trim() ? [value.trim()] : []
    if (value instanceof Collection) return value.collectMany { normalizeList(it) }
    if (value.getClass().isArray()) return value.toList().collectMany { normalizeList(it) }
    return [value]
}

// Вспомогательный SHA-256 для ключей кеша и папок со сгенерированными артефактами.
def sha256Text(def value) {
    def digest = java.security.MessageDigest.getInstance("SHA-256")
        .digest(value.toString().getBytes("UTF-8"))
    return digest.collect { String.format("%02x", ((int) it) & 0xff) }.join("")
}

// Приводит переменные окружения из словаря или списка KEY=VALUE к словарю.
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

// Преобразует итоговый словарь переменных окружения обратно в значения для Jenkins withEnv.
def envMapToAssignments(def envMap) {
    if (!envMap) return []
    return envMap.collect { key, value -> "${key}=${value}" }
}

// Короткое имя проекта для логов; полные пути делают логи SBOM нечитаемыми.
def getPathTail(def path) {
    return path?.toString()?.tokenize('/')?.last() ?: ""
}

// Экранирует путь для shell-команд, где список файлов собирается динамически.
def shellQuote(def value) {
    return "'${value.toString().replace("'", "'\"'\"'")}'"
}

// Сохраняет совместимость обертки инструментов и настроек NodeJS с исходным SBOM-скриптом.
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

// Используем Jenkins withMaven для Maven, JDK, настроек и локального репозитория, но выключаем неявные публикаторы отчетов.
// Без publisherStrategy=EXPLICIT Pipeline Maven может запускать публикаторы JaCoCo во время вызовов mvn из cdxgen.
def wrapMaven(def config, extension, def closure) {
    def result = closure
    def mavenHome = extension.maven?.home ?: config.maven?.home
    def jdk = extension.maven?.jdk ?: config.maven?.jdk ?: "openjdk-21"
    def mavenSettingsConfig = extension.maven?.settings_id ?: config.maven?.settings_id
    def mavenLocalRepo = extension.maven?.local_repo ?: '$workspace/.m2'
    if (config.maven || extension.maven) {
        result = {
            withMaven(
                maven: mavenHome,
                jdk: jdk,
                mavenSettingsConfig: mavenSettingsConfig,
                mavenLocalRepo: mavenLocalRepo,
                publisherStrategy: 'EXPLICIT'
            ) {
                closure()
            }
        }
    }
    return result
}

// Отдаёт settings.xml как реальный файл, чтобы MVN_ARGS мог передать "-s <file>" в Maven, запущенный cdxgen.
def wrapMavenSettingsFile(def mavenSettingsId, def closure) {
    if (!mavenSettingsId) return closure

    return {
        configFileProvider([configFile(fileId: mavenSettingsId, variable: "MAVEN_SETTINGS_FILE")]) {
            closure()
        }
    }
}

// Настройки Maven могут быть заданы глобально в pipeline.yml или прямо в расширении.
def getMavenSettingsId(def config, def extension) {
    return extension.maven?.settings_id ?: config.maven?.settings_id
}

// Исключение директорий работает по префиксу, потому что исходные и сгенерированные корни передаются полными путями.
def isExcludedDir(def path, def excludedDirs) {
    return normalizeList(excludedDirs).any { excluded ->
        path == excluded || path.startsWith("${excluded}/")
    }
}

// Собирает выражение prune для find(1), чтобы пропустить исходники, уже покрытые существующим SBOM или кешем.
def findPruneExpression(def excludedDirs) {
    if (!excludedDirs) return ""

    def expressions = excludedDirs.collect { excluded ->
        "-path \"${excluded}\" -o -path \"${excluded}/*\""
    }.join(" -o ")
    return "\\( ${expressions} \\) -prune -o"
}

// Сгенерированные корни анализа лежат внутри своего проекта, поэтому исключения уровня проекта покрывают их тоже.
def getGeneratedAnalysisDir(def projectDir, def name) {
    return "${projectDir}/.sbom-cyclonedx/${name}"
}

// Пересобирает SDK *.pom файлы как Maven-проекты внутри корня проекта-владельца.
// Пустые сгенерированные папки не возвращаются, чтобы cdxgen не сканировал бесполезные корни.
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

// Записывает восстановленную Maven POM-иерархию из разобранных POM-моделей.
void createPomHirarchy(def paths) {
    paths.each { info ->
        dir(info.dest) {
            writeMavenPom(model: info.pom, file: "pom.xml")
        }
    }
}

// Преобразует разобранные POM-модели в пути назначения с восстановленной структурой родителя и модулей.
def createPaths(def poms) {
    poms.collect { pomKey, pomInfo ->
        [pom: pomInfo.pom, dest: getDestPath(pomInfo, poms, pomKey)]
    }
}

// Идёт по связям parent POM, чтобы положить дочерние модули под восстановленного родителя.
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

// Распаковывает tgz-архивы внутри проекта-владельца, чтобы обычные исключения проекта покрывали извлеченное содержимое.
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
            sh shellScript("""
                mkdir -p "${objectFilePath}"
                tar -xvzf "${tgzPath}" -C "${objectFilePath}"
            """)
        }

        if (tgzPaths) {
            generatedDirs << tgzDir
        }
    }

    return generatedDirs
}

// Разбирает исходные *.pom файлы и очищает существующие модули перед сборкой чистой иерархии.
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

// cyclonedx-cli hierarchical merge строит ref корневого компонента как group.name@version.
def getRootSbomBomRef(def gavtc, def code) {
    def group = gavtc.groupId?.toString()?.trim()
    def name = code?.toString()?.trim()
    def version = gavtc.version?.toString()?.trim()
    def base = group ? "${group}.${name}" : name
    return "${base}@${version}"
}

// Базовый компонент приложения в конце объединяется со всеми отсканированными SBOM проектов.
void generateSBOMTemplate(String sbomTemplatePath, def gavtc, def code) {
    def rootBomRef = getRootSbomBomRef(gavtc, code)
    writeJSON file: sbomTemplatePath, json: [
        bomFormat: "CycloneDX",
        metadata: [
            component: [
                type: "application",
                "bom-ref": rootBomRef,
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

// Собирает список корней, которые должен сканировать cdxgen.
// Существующие исходные директории остаются основными; сгенерированные POM/TGZ корни добавляются только при наличии материала.
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

// Ищет уже существующие SBOM-файлы в исходных репозиториях; такие репозитории исключаются из нового сканирования.
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

// Глобальный блок инструментов и переменных окружения для всех сканов; переопределения source применяются позже к каждой записи.
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

// Переменные окружения расширения нормализуются один раз и затем объединяются с переменными конкретного source.
def getEnvs(def extension) {
    return envMapToAssignments(envAssignmentsToMap(extension.env))
}

// Материал ключа кеша должен учитывать итоговое окружение скана, но не пути инструментов и не расположение бинарника cdxgen.
def getScanBaseEnvMap(def tools, def envs) {
    def result = envAssignmentsToMap(normalizeList(tools) + normalizeList(envs))
    return result.findAll { key, _ ->
        def keyText = key.toString()
        !(keyText.startsWith("PATH+")) && !(keyText in ["CYCLONE", "CYClONE_CLI"])
    }
}

// Старым версиям cdxgen всё ещё нужны явно указанные корни Gradle-проектов.
def getGradlePaths(def globals, def excludedDirs = []) {
    def prune = findPruneExpression(excludedDirs)
    return sh(
        script: "find ${globals.DIR_SRC} ${prune} -name build.gradle -printf '%h\n'",
        returnStdout: true
    ).tokenize("\n")
}

// Репозитории верхнего уровня внутри DIR_SRC считаются независимо настраиваемыми source.
def getSourceDirs(def globals) {
    if (!fileExists(globals.DIR_SRC)) return []

    return sh(
        script: "find ${globals.DIR_SRC} -maxdepth 1 -type d -not -path '${globals.DIR_SRC}' -not -empty",
        returnStdout: true
    ).tokenize("\n")
}

// Пользовательские SBOM могут быть объединены в итоговый корневой SBOM.
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

// Нормализует настройки кеша только до активных бекендов Nexus.
// cache: [] намеренно означает "нет активного кеша".
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

// Делает склейку URL/prefix предсказуемой независимо от начальных и конечных слешей в YAML.
def trimSlashes(def value, boolean leading, boolean trailing) {
    def result = value?.toString() ?: ""
    if (leading) result = result.replaceFirst(/^\/+/, "")
    if (trailing) result = result.replaceFirst(/\/+$/, "")
    return result
}

// Группирует одинаковые настройки Nexus-кеша, чтобы временные директории переиспользовались на один бекенд.
def cacheConfigKey(def cacheConfig) {
    if (!cacheConfig) return "none"
    return sha256Text(cacheConfig.collect { key, value -> "${key}=${value}" }.sort().join("\n"))
}

// Поиск переопределений source поддерживает и имя репозитория, и пути вложенных проектов.
def getProjectSourceName(def globals, def projectDir) {
    if (projectDir?.startsWith("${globals.DIR_SRC}/")) {
        return projectDir.substring("${globals.DIR_SRC}/".length()).tokenize('/').first()
    }

    return getPathTail(projectDir)
}

// Переопределения конкретного source могут менять args/env/tools и заменять или отключать кеш.
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

// Сопоставляет переопределения по абсолютному пути, пути относительно DIR_SRC, имени конечной папки или первому сегменту source.
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

// Tools конкретного source добавляются в PATH только для записей, относящихся к этому source.
def getSourceToolEnvs(def sourceOverride) {
    def result = []
    normalizeList(sourceOverride?.tools).eachWithIndex { toolName, index ->
        def toolPath = tool name: toolName.toString()
        if (fileExists("${toolPath}/bin")) toolPath = "${toolPath}/bin"
        result << "PATH+SOURCE_TOOL_${index}_PATH=${toolPath}"
    }
    return result
}

// Кеш source работает как полная замена, а не merge: если есть sources[].cache, глобальный кеш игнорируется.
def getEffectiveCacheConfig(def sourceOverride, def globalCacheConfigs) {
    def cacheConfigs = sourceOverride?.hasCache ? sourceOverride.cacheConfigs : globalCacheConfigs
    return normalizeList(cacheConfigs).find { it }
}

// Итоговая конфигурация скана проекта после объединения глобальных значений расширения и переопределения source.
def getScanConfig(def globals, def sourceOverrides, def globalCacheConfigs, def baseArgs, def baseEnvMap, def projectDir) {
    def sourceOverride = findSourceOverride(globals, sourceOverrides, projectDir)
    return [
        args: normalizeList(baseArgs) + normalizeList(sourceOverride?.args),
        env: [:] + baseEnvMap + (sourceOverride?.env ?: [:]),
        tools: getSourceToolEnvs(sourceOverride),
        cacheConfig: getEffectiveCacheConfig(sourceOverride, globalCacheConfigs)
    ]
}

// Разделяет type-аргументы cdxgen, чтобы сканы манифестов кешировались, а сканы артефактов оставались без кеша.
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

// Возвращает нормализованные аргументы "-t <type>" после разделения типов.
def withCdxgenTypes(def cleanedArgs, def scanTypes) {
    def result = normalizeList(cleanedArgs).collect { it }
    normalizeList(scanTypes).each { scanType ->
        result += ["-t", scanType.toString()]
    }
    return result
}

// Стабильный id для логов, путей SBOM и материала кеша; индексы не используются, чтобы ключи кеша не дрейфовали.
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

// Один проект может дать две независимые записи: кешируемый скан манифестов и некешируемый скан артефактов.
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

// Общая короткая метка для логов кеша и сканирования.
def getEntryLogLabel(def entry) {
    return "project=${getPathTail(entry.projectDir)}, type=${entry.type}, id=${entry.projectId}, key=${entry.cacheKey ?: '-'}"
}

// Ключ кеша строится только по стабильным файлам манифестов и lock-файлам; бинарные артефакты намеренно исключены.
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
    // Игнорируем директории сборки и кеша: их содержимое меняется между запусками и портит ключи кеша.
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

// Переменные окружения влияют на разрешение зависимостей, поэтому стабильные значения окружения входят в ключ кеша.
def getEntryEnvMaterial(def entry) {
    def envMap = (entry.effectiveEnv ?: [:]).findAll { key, _ ->
        def keyText = key.toString()
        !(keyText.startsWith("PATH+")) && !(keyText in ["CYCLONE", "CYClONE_CLI"])
    }
    return envMapToAssignments(envMap).sort().join("\n")
}

// Решает, можно ли кешировать запись, и готовит стабильный ключ объекта Nexus.
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

// Maven-layout в Nexus требует, чтобы имя файла начиналось с artifactId-version.
// Пример: sbom-cache/v1/sbom-cache-v1-<hash>.json.
def getCacheObjectUrl(def cacheConfig, def entry) {
    if (!cacheConfig || !entry.cacheKey) return null
    def cacheFilePrefix = cacheConfig.prefix.toString().tokenize("/").join("-")
    return "${cacheConfig.url}/${cacheConfig.prefix}/${cacheFilePrefix}-${entry.cacheKey}.json"
}

// Временные файлы ответов GET/PUT изолированы для каждой настройки бекенда Nexus.
def prepareCacheContext(def globals, def cacheConfig) {
    if (!cacheConfig) return null

    def cacheDir = "${globals.DIR_TMP}/generateSBOMCyclonedx-cache-${cacheConfigKey(cacheConfig).take(12)}"
    sh "mkdir -p \"${cacheDir}\""
    return cacheConfig + [dir: cacheDir]
}

// Готовит уникальные имена переменных окружения для credentials конкретного Nexus-бекенда.
void prepareCacheCredentialVars(def cacheContext) {
    if (!cacheContext?.creds || cacheContext.cacheUsernameVar) return

    def suffix = cacheConfigKey(cacheContext).take(12).replaceAll(/[^A-Za-z0-9_]/, "_")
    cacheContext.cacheUsernameVar = "SBOM_CACHE_USERNAME_${suffix}"
    cacheContext.cachePasswordVar = "SBOM_CACHE_PASSWORD_${suffix}"
}

// Биндит Nexus credentials до запуска parallel, потому что local CIJE runner падает на withCredentials внутри веток.
void runWithCacheCredentials(def cacheContexts, def closure) {
    def bindings = []
    def seen = [] as Set

    normalizeList(cacheContexts).findAll { it?.creds }.each { cacheContext ->
        prepareCacheCredentialVars(cacheContext)
        def bindingKey = "${cacheContext.creds}:${cacheContext.cacheUsernameVar}:${cacheContext.cachePasswordVar}"
        if (!seen.contains(bindingKey)) {
            seen << bindingKey
            bindings << usernamePassword(
                credentialsId: cacheContext.creds,
                usernameVariable: cacheContext.cacheUsernameVar,
                passwordVariable: cacheContext.cachePasswordVar
            )
        }
    }

    if (!bindings) {
        closure()
        return
    }

    withCredentials(bindings) {
        closure()
    }
}

// Возвращает curl-аргумент авторизации из заранее привязанных переменных окружения.
def getCacheCurlAuthArg(def cacheContext) {
    if (!cacheContext?.creds) return ""
    if (!cacheContext.cacheUsernameVar || !cacheContext.cachePasswordVar) return ""
    return "-u \"\$${cacheContext.cacheUsernameVar}:\$${cacheContext.cachePasswordVar}\""
}

// Выполняет Nexus GET. Учетные данные уже привязаны снаружи, чтобы не дергать withCredentials в parallel.
def runCacheGet(def cacheContext, def url, def outputPath) {
    def curlScript = { authArg ->
        return """
            set +e
            http_code=\$(curl -k -sS ${authArg} -w "%{http_code}" -o "${outputPath}" "${url}" 2>"${outputPath}.err")
            curl_status=\$?
            echo "\${curl_status}:\${http_code}"
        """
    }

    return sh(script: curlScript(getCacheCurlAuthArg(cacheContext)), returnStdout: true)?.trim()
}

// Выполняет Nexus PUT с семантикой загрузки, совместимой с Maven-репозиторием.
def runCachePut(def cacheContext, def url, def sourcePath, def outputPath) {
    def curlScript = { authArg ->
        return """
            set +e
            http_code=\$(curl -k -sS ${authArg} -X PUT -T "${sourcePath}" -w "%{http_code}" -o "${outputPath}" "${url}" 2>"${outputPath}.err")
            curl_status=\$?
            echo "\${curl_status}:\${http_code}"
        """
    }

    return sh(script: curlScript(getCacheCurlAuthArg(cacheContext)), returnStdout: true)?.trim()
}

// Curl печатает "<curl_status>:<http_code>"; null или пустой ответ считаем транспортной ошибкой.
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

// Копирует через шаги Jenkins, а не через shell cp, чтобы работало и в Jenkins, и в локальном CIJE runner.
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

// В кеше полезны только SBOM с непустым списком components; пустые SBOM считаются промахом кеша.
def isNonEmptySbom(def sbomPath) {
    if (!sbomPath || !fileExists(sbomPath)) return false

    // Проверяем кешевый BOM через jq, чтобы не загружать JSON в Jenkins/Groovy.
    // jq -e возвращает 0 только если components является непустым массивом.
    def status = sh(
        script: "jq -e '(.components // []) | type == \"array\" and length > 0' ${shellQuote(sbomPath)} >/dev/null 2>&1",
        returnStatus: true
    )
    if (status != 0) {
        echo("SBOM cache: файл ${sbomPath} пустой или не читается как CycloneDX JSON")
    }
    return status == 0
}

// Восстанавливает SBOM из Nexus, если объект существует и содержит components.
// Любая проблема кеша только помечает запись и даёт сценарию продолжить новый скан.
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

// Сохраняет заново сгенерированный SBOM в Nexus.
// PUT защищён предварительным GET, потому что Maven-репозитории hosted-типа часто отклоняют перезапись.
def saveToCache(def cacheContext, def entry) {
    if (!entry.cacheKey) {
        entry.cacheSaveStatus = "skip"
        echo("SBOM cache SAVE SKIP: backend=${cacheContext.backend}, ${getEntryLogLabel(entry)}, reason=no cache key")
        return false
    }
    if (entry.cacheStatus == "hit") {
        entry.cacheSaveStatus = "skip"
        echo("SBOM cache SAVE SKIP: backend=${cacheContext.backend}, ${getEntryLogLabel(entry)}, reason=already restored from cache")
        return false
    }
    if (!isNonEmptySbom(entry.sbomPath)) {
        entry.cacheSaveStatus = "skip"
        echo("SBOM cache SAVE SKIP: backend=${cacheContext.backend}, ${getEntryLogLabel(entry)}, reason=sbom is empty or missing")
        return false
    }

    def url = getCacheObjectUrl(cacheContext, entry)
    // Предварительная проверка предотвращает повторную загрузку, если кеш уже заполнил ранний запуск или другая ветка.
    def existingPath = "${cacheContext.dir}/${entry.projectId}-${entry.cacheKey}.exists"
    def existingResponse = parseCacheResponse(runCacheGet(cacheContext, url, existingPath))
    if (existingResponse.curlStatus == 0 && existingResponse.httpCode == 200) {
        entry.cacheSaveStatus = "skip"
        echo("SBOM cache SAVE SKIP: backend=${cacheContext.backend}, ${getEntryLogLabel(entry)}, reason=already exists")
        return false
    }
    if (existingResponse.curlStatus != 0 || existingResponse.httpCode != 404) {
        entry.cacheSaveStatus = "failed"
        unstable("SBOM cache SAVE CHECK FAILED: backend=${cacheContext.backend}, ${getEntryLogLabel(entry)}, http=${existingResponse.httpCode}, curl=${existingResponse.curlStatus}")
        return false
    }

    def outputPath = "${cacheContext.dir}/${entry.projectId}-${entry.cacheKey}.put"
    def response = parseCacheResponse(runCachePut(cacheContext, url, entry.sbomPath, outputPath))

    if (response.curlStatus != 0 || !(response.httpCode in [200, 201, 204])) {
        // Если две ветки соревнуются, Nexus может отклонить один PUT, хотя объект уже доступен.
        def afterPutPath = "${cacheContext.dir}/${entry.projectId}-${entry.cacheKey}.after-put"
        def afterPutResponse = parseCacheResponse(runCacheGet(cacheContext, url, afterPutPath))
        if (afterPutResponse.curlStatus == 0 && afterPutResponse.httpCode == 200) {
            entry.cacheSaveStatus = "skip"
            echo("SBOM cache SAVE SKIP: backend=${cacheContext.backend}, ${getEntryLogLabel(entry)}, reason=already exists after race")
            return false
        }

        entry.cacheSaveStatus = "failed"
        unstable("SBOM cache SAVE FAILED: backend=${cacheContext.backend}, ${getEntryLogLabel(entry)}, http=${response.httpCode}, curl=${response.curlStatus}")
        return false
    }

    entry.cacheSaveStatus = "saved"
    echo("SBOM cache SAVE: backend=${cacheContext.backend}, ${getEntryLogLabel(entry)}")
    return true
}

// Версия cdxgen меняет поведение, поэтому входит в материал кеша скана манифестов.
def getCdxgenVersion(def cdxgenPath) {
    return sh(script: "\${CYCLONE}/${cdxgenPath} --version 2>&1 || true", returnStdout: true).trim()
}

// Собирает окружение для одной записи скана, включая инструменты и переменные конкретного source.
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

// Pipeline Maven plugin проверяет этот маркер перед публикацией сгенерированных отчетов покрытия.
void writeMavenCoverageSkipMarker(def markerDir) {
    if (!markerDir || !fileExists(markerDir)) return

    dir(markerDir) {
        writeFile file: ".skip-publish-coverage-results", text: ""
    }
}

// Маркер проекта покрывает запуски Maven, которые cdxgen делает из директории проекта.
void ensureMavenCoveragePublisherSkipped(def entry) {
    writeMavenCoverageSkipMarker(entry?.projectDir)
}

// Маркер workspace покрывает запуски Maven, у которых build home резолвится в workspace Jenkins.
void ensureWorkspaceMavenCoveragePublisherSkipped() {
    writeMavenCoverageSkipMarker(env.WORKSPACE ?: pwd())
}

// Запускает cdxgen для одной записи. "-r" здесь не добавляется: рекурсия управляется аргументами пользователя.
void runScan(def entry, def cdxgenPath, def extraExcludeDirs = []) {
    def scanArgs = normalizeList(entry.cdxgenArgs) + normalizeList(extraExcludeDirs).collectMany { dir ->
        ["--exclude", "\"${dir}/**\""]
    }
    entry.scanned = true
    echo("SBOM scan HOST: ${getEntryLogLabel(entry)}")
    ensureMavenCoveragePublisherSkipped(entry)
    withEnv(scanEnvForEntry(entry)) {
        sh "\${CYCLONE}/${cdxgenPath} -o \"${entry.sbomPath}\" ${scanArgs.join(' ')} \"${entry.projectDir}\""
    }
}

// extension.parallel по умолчанию true; только явный false отключает Jenkins parallel.
def isParallelEnabled(def extension) {
    if (extension.parallel == null) return true
    if (extension.parallel instanceof Boolean) return extension.parallel
    return extension.parallel.toString().trim().toLowerCase() != "false"
}

// Параллельный merge включается только явно, чтобы не менять поведение старых конфигов.
def isParallelMergeEnabled(def extension) {
    if (extension.parallel_merge instanceof Boolean) return extension.parallel_merge
    return extension.parallel_merge?.toString()?.trim()?.toLowerCase() == "true"
}

// Общий запускатель фаз. Сценарий записи сейчас использует его один раз с phaseName="ENTRY".
void runEntriesPhase(def phaseName, def entries, boolean parallelEnabled, def closure) {
    def phaseEntries = normalizeList(entries).findAll { it }
    echo("SBOM ${phaseName} parallel: enabled=${parallelEnabled}, branches=${phaseEntries.size()}")
    if (!phaseEntries) return

    if (!parallelEnabled) {
        phaseEntries.each { entry -> closure(entry) }
        return
    }

    def branches = [failFast: false]
    phaseEntries.eachWithIndex { entry, index ->
        def phaseEntry = entry
        def branchName = "SBOM ${phaseName} ${index} ${phaseEntry.projectId ?: getPathTail(phaseEntry.projectDir)}"
        branches[branchName] = {
            closure(phaseEntry)
        }
    }
    parallel branches
}

void ensureParentDirectory(def filePath) {
    def slashIndex = filePath.lastIndexOf("/")
    if (slashIndex > 0) {
        sh "mkdir -p ${shellQuote(filePath.substring(0, slashIndex))}"
    }
}

def getSbomSubjectName(def sbomPath) {
    def path = sbomPath?.toString()
    if (!path) return "sbom"

    // Для synthetic metadata.component используем имя папки, где лежит SBOM.
    // Так root входного BOM получается человекочитаемым, но не влияет на package graph.
    def slashIndex = path.lastIndexOf("/")
    if (slashIndex > 0) {
        return getPathTail(path.substring(0, slashIndex)) ?: getPathTail(path) ?: "sbom"
    }
    return getPathTail(path) ?: "sbom"
}

void writeJsonArrayFile(def filePath, def values) {
    writeTextFile(filePath, groovy.json.JsonOutput.toJson(normalizeList(values)))
}

void writeTextFile(def filePath, def text) {
    ensureParentDirectory(filePath)
    writeFile file: filePath, text: text.toString()
}

void writeJqFilterFile(def filePath, def filterText) {
    // jq-фильтр маленький, поэтому его безопасно писать через Jenkins writeFile.
    // Большой SBOM при этом остается во внешнем jq-процессе и не попадает в память Groovy.
    writeTextFile(filePath, filterText.toString().stripIndent().trim() + "\n")
}

def shellScript(def scriptText) {
    // В коде shell-блоки остаются читаемыми с отступами, а Jenkins получает команду без пустой первой строки.
    return scriptText.toString().stripIndent().trim()
}

def parseSbomGraphInfo(def graphText) {
    def info = [
        rootRef: "",
        directRefs: new LinkedHashSet(),
        knownRefs: new LinkedHashSet(),
        dependencyRefs: new LinkedHashSet(),
        edges: [:].withDefault { new LinkedHashSet() }
    ]

    // jq отдает только компактный graph index, а не весь BOM.
    // Формат строк: KIND<TAB>ref или EDGE<TAB>parent<TAB>child.
    graphText.toString().readLines().each { line ->
        def parts = line.split("\t", -1)
        if (parts.size() >= 2) {
            def kind = parts[0]
            def ref = parts[1]?.trim()
            if (kind == "ROOT") {
                info.rootRef = ref ?: ""
            } else if (kind == "DIRECT" && ref) {
                info.directRefs << ref
            } else if (kind == "KNOWN" && ref) {
                info.knownRefs << ref
            } else if (kind == "DEP" && ref) {
                info.dependencyRefs << ref
            } else if (kind == "EDGE" && ref && parts.size() >= 3) {
                def childRef = parts[2]?.trim()
                if (childRef) info.edges[ref] << childRef
            }
        }
    }

    return info
}

def collectReachableGraphRefs(def edges, def rootRef, def rootDependsOn) {
    def reachable = new LinkedHashSet()
    def queue = new ArrayDeque()
    if (rootRef) {
        // Обход всегда начинается от subject/root текущего input BOM.
        reachable << rootRef
        queue.add(rootRef)
    }

    // Обычный BFS по dependsOn, чтобы понять какие refs реально достижимы от root.
    while (!queue.isEmpty()) {
        def ref = queue.removeFirst()
        def childRefs = ref == rootRef ? rootDependsOn : edges[ref]
        childRefs.each { childRef ->
            if (!reachable.contains(childRef)) {
                reachable << childRef
                queue.add(childRef)
            }
        }
    }

    return reachable
}

def getPreparedDependencyGraph(def info) {
    def rootRef = info.rootRef
    def rootDependsOn = new LinkedHashSet(info.edges[rootRef] ?: [])

    // Если root dependency уже непустая, считаем ее источником истины.
    // Иначе берем graph roots/direct inventory refs, чтобы BOM без root graph не остался пустым.
    def hasUsableRootDependency = rootDependsOn.size() > 0
    if (!hasUsableRootDependency) {
        def childRefs = new LinkedHashSet()
        info.edges.each { _, children ->
            children.findAll { it != rootRef }.each { childRefs << it }
        }

        def graphRoots = info.dependencyRefs.findAll { ref ->
            ref && ref != rootRef && info.knownRefs.contains(ref) && !childRefs.contains(ref)
        }
        def fallbackRefs = graphRoots ?: info.directRefs.findAll { it != rootRef }
        fallbackRefs.each { ref -> rootDependsOn << ref }
    }

    def reachable = collectReachableGraphRefs(info.edges, rootRef, rootDependsOn)

    // Недостижимые inventory refs подвешиваем напрямую к root.
    // Это не выдумывает transitive edges, а только не дает итоговому SBOM "обрываться".
    info.knownRefs.findAll { ref -> ref != rootRef && !reachable.contains(ref) }.each { ref ->
        rootDependsOn << ref
    }

    // CycloneDX отличает "нет dependency entry" от "точно нет зависимостей".
    // Поэтому для leaf refs добавляем пустую dependency entry, если ее не было.
    def dependencyRefs = new LinkedHashSet(info.dependencyRefs)
    dependencyRefs << rootRef
    def leafRefs = info.knownRefs.findAll { ref -> ref != rootRef && !dependencyRefs.contains(ref) }

    return [
        rootDependsOn: rootDependsOn.collect { it },
        leafRefs: leafRefs.collect { it }
    ]
}

void normalizeSbomJsonShape(def sbomPath, def normalizedPath, def subjectName, def syntheticRootRef) {
    def normalizeShapeFilter = '''
        def as_array:
          if . == null then []
          elif type == "array" then .
          elif type == "object" then [.]
          else [] end;

        def as_object:
          if type == "object" then . else {} end;

        def text:
          if . == null then "" else tostring end;

        def generated_ref($prefix; $seed):
          $prefix + ($seed | @uri);

        def normalize_component($seed):
          if type != "object" then .
          else
            (.name // "component" | text) as $name
            | (.version // "unknown" | text) as $version
            | (.type // "" | text) as $type
            | (.group // "" | text) as $group
            | .["bom-ref"] = ((.["bom-ref"] // .purl // generated_ref("generated-"; [$seed, $type, $group, $name, $version] | join(":"))) | text)
            | .components = ((.components | as_array) | to_entries | map(. as $entry | $entry.value | normalize_component($seed + ":" + ($entry.key | tostring))))
          end;

        def normalize_service($seed):
          if type != "object" then .
          else
            (.name // "service" | text) as $name
            | .["bom-ref"] = ((.["bom-ref"] // generated_ref("generated-service-"; [$seed, $name] | join(":"))) | text)
          end;

        def direct_refs:
          [
            ((.components | as_array)[]? | select(type == "object") | .["bom-ref"]),
            ((.services | as_array)[]? | select(type == "object") | .["bom-ref"])
          ]
          | map(select(. != null and (tostring | length > 0)) | tostring);

        .metadata = ((.metadata // {}) | as_object)
        | .components = ((.components | as_array) | to_entries | map(. as $entry | $entry.value | normalize_component("component:" + ($entry.key | tostring))))
        | .services = ((.services | as_array) | to_entries | map(. as $entry | $entry.value | normalize_service("service:" + ($entry.key | tostring))))
        | if (.metadata.component | type) == "object" then
            .metadata.component |= (
              .["bom-ref"] = ((.["bom-ref"] // .purl // $syntheticRootRef) | text)
              | if ((.type // "" | text) == "") then .type = "application" else . end
              | if ((.name // "" | text) == "") then .name = $subjectName else . end
              | if ((.version // "" | text) == "") then .version = "0" else . end
            )
          elif ((direct_refs | length) > 0) then
            .metadata.component = {
              type: "application",
              "bom-ref": $syntheticRootRef,
              name: $subjectName,
              version: "0"
            }
          else
            .
          end
    '''
    def filterPath = "${normalizedPath}.normalize-shape-${UUID.randomUUID().toString()}.jq"
    writeJqFilterFile(filterPath, normalizeShapeFilter)

    // jq нормализует форму большого BOM во внешнем процессе: Groovy не читает весь JSON.
    // Фильтр передаем через файл, чтобы Jenkins-log не печатал длинный jq-код inline.
    sh shellScript("""
        set -e
        command -v jq >/dev/null 2>&1 || { echo 'SBOM hierarchical normalize requires jq'; exit 1; }
        filter_file=${shellQuote(filterPath)}
        trap 'rm -f "\$filter_file"' EXIT

        jq --arg subjectName ${shellQuote(subjectName)} --arg syntheticRootRef ${shellQuote(syntheticRootRef)} \
            -f "\$filter_file" ${shellQuote(sbomPath)} > ${shellQuote(normalizedPath)}

        rm -f "\$filter_file"
        trap - EXIT
    """)
}

def collectSbomGraphInfo(def normalizedPath) {
    def graphInfoFilter = '''
        def as_array:
          if . == null then []
          elif type == "array" then .
          elif type == "object" then [.]
          else [] end;

        def component_objects($items):
          ($items | as_array)[]?
          | select(type == "object")
          | ., component_objects(.components);

        def direct_refs:
          [
            ((.components | as_array)[]? | select(type == "object") | .["bom-ref"]),
            ((.services | as_array)[]? | select(type == "object") | .["bom-ref"])
          ]
          | map(select(. != null and (tostring | length > 0)) | tostring);

        def known_refs:
          [
            (component_objects(.components) | .["bom-ref"]),
            ((.services | as_array)[]? | select(type == "object") | .["bom-ref"])
          ]
          | map(select(. != null and (tostring | length > 0)) | tostring);

        (.metadata.component["bom-ref"] // "" | tostring) as $rootRef
        | "ROOT\\t\\($rootRef)",
          (direct_refs[] | "DIRECT\\t\\(.)"),
          (known_refs[] | "KNOWN\\t\\(.)"),
          ((.dependencies | as_array)[]? | select(type == "object") | (.ref // "" | tostring) as $ref | select($ref != "") | "DEP\\t\\($ref)"),
          ((.dependencies | as_array)[]? | select(type == "object") | (.ref // "" | tostring) as $ref | select($ref != "") | (.dependsOn | as_array)[]? | tostring | "EDGE\\t\\($ref)\\t\\(.)")
    '''
    def filterPath = "${normalizedPath}.graph-info-${UUID.randomUUID().toString()}.jq"
    writeJqFilterFile(filterPath, graphInfoFilter)

    try {
        return parseSbomGraphInfo(sh(
            script: shellScript("""
                set -e
                jq -r -f ${shellQuote(filterPath)} ${shellQuote(normalizedPath)}
            """),
            returnStdout: true
        ))
    } finally {
        sh "rm -f ${shellQuote(filterPath)}"
    }
}

void applyNormalizedDependencyGraph(def normalizedPath, def rootRef, def rootDependsOn, def leafRefs) {
    def dependencyGraphFilter = '''
        def as_array:
          if . == null then []
          elif type == "array" then .
          else [] end;

        ($rootDependsOn[0]) as $rootChildren
        | ($leafRefs[0]) as $leafs
        | (.dependencies | as_array | map(select(type == "object"))) as $deps
        | ($deps | map(select((.ref // "" | tostring) == $rootRef)) | first // {ref: $rootRef}) as $rootDependency
        | .dependencies = (
            [($rootDependency | .ref = $rootRef | .dependsOn = $rootChildren)]
            + ($deps | map(select((.ref // "" | tostring) != $rootRef)))
            + ($leafs | map({ref: .}))
          )
    '''
    def rootDependsOnPath = "${normalizedPath}.root-depends-on-${UUID.randomUUID().toString()}.json"
    def leafRefsPath = "${normalizedPath}.leaf-refs-${UUID.randomUUID().toString()}.json"
    def tmpPath = "${normalizedPath}.deps-${UUID.randomUUID().toString()}.tmp"
    def filterPath = "${normalizedPath}.dependencies-${UUID.randomUUID().toString()}.jq"

    writeJsonArrayFile(rootDependsOnPath, rootDependsOn)
    writeJsonArrayFile(leafRefsPath, leafRefs)
    writeJqFilterFile(filterPath, dependencyGraphFilter)

    // jq применяет рассчитанные Groovy списки к BOM и пишет новую копию атомарной заменой.
    sh shellScript("""
        set -e
        tmp_file=${shellQuote(tmpPath)}
        root_depends_on_file=${shellQuote(rootDependsOnPath)}
        leaf_refs_file=${shellQuote(leafRefsPath)}
        filter_file=${shellQuote(filterPath)}
        trap 'rm -f "\$tmp_file" "\$root_depends_on_file" "\$leaf_refs_file" "\$filter_file"' EXIT

        jq --arg rootRef ${shellQuote(rootRef)} --slurpfile rootDependsOn "\$root_depends_on_file" \
            --slurpfile leafRefs "\$leaf_refs_file" -f "\$filter_file" ${shellQuote(normalizedPath)} > "\$tmp_file"

        mv "\$tmp_file" ${shellQuote(normalizedPath)}
        rm -f "\$root_depends_on_file" "\$leaf_refs_file" "\$filter_file"
        trap - EXIT
    """)
}

def normalizeSbomForHierarchicalMerge(def sbomPath, def normalizedDir, int index) {
    def normalizedPath = "${normalizedDir}/normalized-${index}.json"
    def syntheticRootRef = "generated-root-${sha256Text(sbomPath).take(32)}"
    def subjectName = getSbomSubjectName(sbomPath)

    // Читаем и переписываем большой input BOM через jq, а не через Jenkins readJSON/writeJSON.
    normalizeSbomJsonShape(sbomPath, normalizedPath, subjectName, syntheticRootRef)

    def graphInfo = collectSbomGraphInfo(normalizedPath)
    def rootRef = graphInfo.rootRef?.toString()?.trim()
    if (!rootRef) {
        // Пустой BOM без subject и inventory не несет информации, поэтому его безопасно пропустить.
        echo("SBOM MERGE hierarchical skip: ${sbomPath}, reason=no metadata component and empty inventory")
        sh "rm -f ${shellQuote(normalizedPath)}"
        return null
    }

    // Делаем dependency graph входного BOM явным до CLI:
    // сохраняем существующие edges, добавляем root/leaf entries только там, где их не хватает.
    def preparedGraph = getPreparedDependencyGraph(graphInfo)
    applyNormalizedDependencyGraph(normalizedPath, rootRef, preparedGraph.rootDependsOn, preparedGraph.leafRefs)

    // Пишем нормализованную копию во временную папку, исходный SBOM в проекте не меняем.
    echo("SBOM MERGE hierarchical normalize: ${sbomPath} -> ${normalizedPath}, reason=metadata/root dependency normalization")
    return normalizedPath
}

def prepareHierarchicalMergeInputs(def inputFiles, def globals) {
    // Берем только реально существующие файлы, чтобы merge не падал на пропавших/пустых путях.
    def files = normalizeList(inputFiles).findAll { fileExists(it) }.unique()
    if (!files) return []

    // Все подготовленные BOM кладем в отдельную временную директорию текущего запуска.
    def normalizedDir = "${globals.DIR_TMP}/generateSBOMCyclonedx-hierarchical-${UUID.randomUUID().toString()}"
    sh "mkdir -p ${shellQuote(normalizedDir)}"

    // Нормализуем каждый входной BOM отдельно и пропускаем только полностью пустые BOM.
    def result = []
    files.eachWithIndex { sbomPath, index ->
        def normalizedPath = normalizeSbomForHierarchicalMerge(sbomPath, normalizedDir, index)
        if (normalizedPath) result << normalizedPath
    }
    return result.unique()
}

void mergeHierarchicalSbomFiles(def inputFiles, def outputPath, def cyclonedxCliPath, def specVersion, def sbomTemplatePath) {
    // Создаем папку результата перед запуском CLI.
    ensureParentDirectory(outputPath)

    // Единственное место, где строится общая hierarchy между BOM:
    // template и каждый input BOM передаются в штатный cyclonedx-cli merge --hierarchical.
    sh shellScript("""
        command -v jq >/dev/null 2>&1 || { echo 'SBOM hierarchical merge requires jq'; exit 1; }

        root_group=\$(jq -r '.metadata.component.group // ""' ${shellQuote(sbomTemplatePath)})
        root_name=\$(jq -r '.metadata.component.name // ""' ${shellQuote(sbomTemplatePath)})
        root_version=\$(jq -r '.metadata.component.version // ""' ${shellQuote(sbomTemplatePath)})

        if [ -z "\$root_name" ] || [ -z "\$root_version" ]; then
            echo "SBOM hierarchical merge: root metadata component is missing name/version in ${shellQuote(sbomTemplatePath)}"
            exit 1
        fi

        \${CYClONE_CLI}/${cyclonedxCliPath} merge \
            --input-files ${normalizeList(inputFiles).collect { shellQuote(it) }.join(' ')} \
            --output-file ${shellQuote(outputPath)} \
            --output-format json \
            --output-version ${specVersion} \
            --hierarchical \
            --group "\$root_group" \
            --name "\$root_name" \
            --version "\$root_version"
    """)
}

// Финальная конвертация оставлена отдельным шагом, как в исходном сценарии.
void convertSbomFile(def sbomPath, def specVersion, def cyclonedxCliPath) {
    ensureParentDirectory(sbomPath)
    sh shellScript("""
        \${CYClONE_CLI}/${cyclonedxCliPath} convert \
            --output-version ${specVersion} \
            --input-file ${shellQuote(sbomPath)} \
            --output-file ${shellQuote(sbomPath)}
    """)
}

void finalizeHierarchicalSbom(def sbomPath, def sbomTemplatePath) {
    def rootAliasesFilter = '''
        ($root[0]) as $r
        | ($r["bom-ref"] | tostring) as $rootRef
        | [
            $rootRef,
            ($rootRef + ":" + $rootRef),
            ((.components // [])[]?
              | select(type == "object")
              | (.["bom-ref"] // "" | tostring) as $componentRef
              | (.purl // "" | tostring) as $purl
              | ($r.purl // "" | tostring) as $rootPurl
              | (.group // "" | tostring) as $group
              | ($r.group // "" | tostring) as $rootGroup
              | (.name // "" | tostring) as $name
              | ($r.name // "" | tostring) as $rootName
              | (.version // "" | tostring) as $version
              | ($r.version // "" | tostring) as $rootVersion
              | select(
                  $componentRef == $rootRef
                  or $componentRef == ($rootRef + ":" + $rootRef)
                  or ($purl != "" and $purl == $rootPurl)
                  or ($rootGroup != "" and $group == $rootGroup and $name == $rootName and $version == $rootVersion)
                )
              | $componentRef
            )
          ]
        | map(select(. != ""))
        | unique
    '''
    def replaceRootComponentFilter = '''
        ($root[0]) as $r
        | ($rootRefs[0]) as $refs
        | .metadata = ((.metadata // {}) | if type == "object" then . else {} end)
        | .metadata.component = $r
        | .components = (
            (.components // [])
            | if type == "array" then . else [] end
            | map(
                if type == "object" then
                  (.["bom-ref"] // "" | tostring) as $ref
                  | select(($refs | index($ref)) == null)
                else
                  .
                end
              )
          )
    '''
    def cleanupRootDependencyFilter = '''
        def as_array:
          if . == null then []
          elif type == "array" then .
          else [.] end;

        ($root[0]["bom-ref"] | tostring) as $rootRef
        | ($rootRefs[0]) as $refs
        | (.dependencies | as_array | map(select(type == "object"))) as $deps
        | [$deps[] | select((.ref // "" | tostring) == $rootRef)] as $rootDeps
        | ([$rootDeps[] | (.dependsOn | as_array)[]? | tostring | . as $ref | select(($refs | index($ref)) == null)] | unique) as $rootDependsOn
        | ([$rootDeps[] | (.provides | as_array)[]? | tostring | . as $ref | select(($refs | index($ref)) == null)] | unique) as $rootProvides
        | ({ref: $rootRef, dependsOn: $rootDependsOn} + if ($rootProvides | length) > 0 then {provides: $rootProvides} else {} end) as $rootDependency
        | .dependencies = (
            [$rootDependency]
            + [$deps[]
               | (.ref // "" | tostring) as $ref
               | select($ref != $rootRef and (($refs | index($ref)) == null))]
          )
    '''
    def tmpPath = "${sbomPath}.finalized-${UUID.randomUUID().toString()}.tmp"
    def tmpNextPath = "${tmpPath}.next"
    def rootComponentPath = "${sbomPath}.root-component-${UUID.randomUUID().toString()}.tmp"
    def rootRefsPath = "${sbomPath}.root-refs-${UUID.randomUUID().toString()}.tmp"
    def rootAliasesFilterPath = "${sbomPath}.root-aliases-${UUID.randomUUID().toString()}.jq"
    def replaceRootComponentFilterPath = "${sbomPath}.replace-root-${UUID.randomUUID().toString()}.jq"
    def cleanupRootDependencyFilterPath = "${sbomPath}.cleanup-root-${UUID.randomUUID().toString()}.jq"

    writeJqFilterFile(rootAliasesFilterPath, rootAliasesFilter)
    writeJqFilterFile(replaceRootComponentFilterPath, replaceRootComponentFilter)
    writeJqFilterFile(cleanupRootDependencyFilterPath, cleanupRootDependencyFilter)

    // Финальный cleanup делаем через jq, чтобы Jenkins/Groovy не поднимал большой merged BOM в память.
    // Каждый jq-фильтр делает один маленький шаг: достать root, заменить metadata/component, почистить root dependency.
    sh shellScript("""
        set -e
        command -v jq >/dev/null 2>&1 || { echo 'SBOM hierarchical finalize requires jq'; exit 1; }

        tmp_file=${shellQuote(tmpPath)}
        next_file=${shellQuote(tmpNextPath)}
        root_component_file=${shellQuote(rootComponentPath)}
        root_refs_file=${shellQuote(rootRefsPath)}
        root_aliases_filter_file=${shellQuote(rootAliasesFilterPath)}
        replace_root_filter_file=${shellQuote(replaceRootComponentFilterPath)}
        cleanup_root_filter_file=${shellQuote(cleanupRootDependencyFilterPath)}
        trap 'rm -f "\$tmp_file" "\$next_file" "\$root_component_file" "\$root_refs_file" "\$root_aliases_filter_file" "\$replace_root_filter_file" "\$cleanup_root_filter_file"' EXIT

        jq -e '.metadata.component | select(type == "object" and (."bom-ref" // "" | tostring | length > 0))' \
            ${shellQuote(sbomTemplatePath)} > "\$root_component_file"

        jq --slurpfile root "\$root_component_file" -f "\$root_aliases_filter_file" \
            ${shellQuote(sbomPath)} > "\$root_refs_file"

        jq --slurpfile root "\$root_component_file" --slurpfile rootRefs "\$root_refs_file" \
            -f "\$replace_root_filter_file" ${shellQuote(sbomPath)} > "\$tmp_file"

        jq --slurpfile root "\$root_component_file" --slurpfile rootRefs "\$root_refs_file" \
            -f "\$cleanup_root_filter_file" "\$tmp_file" > "\$next_file"

        mv "\$next_file" ${shellQuote(sbomPath)}
        rm -f "\$tmp_file" "\$root_component_file" "\$root_refs_file" "\$root_aliases_filter_file" "\$replace_root_filter_file" "\$cleanup_root_filter_file"

        trap - EXIT
    """)
}

// hierarchical merge должен видеть template и каждый входной SBOM как отдельные subjects; graph строит cyclonedx-cli.
void mergeSbomFiles(def inputFiles, def mergedPath, def specVersion, def cyclonedxCliPath, def globals, boolean parallelMergeEnabled, def sbomTemplatePath) {
    // Все реальные входные BOM нормализуются до запуска CLI.
    def files = prepareHierarchicalMergeInputs(inputFiles, globals)

    // Template обязательно идет первым input, чтобы он был верхним subject итогового merge.
    def mergeFiles = ([sbomTemplatePath] + files.findAll { it != sbomTemplatePath }).unique()

    echo("SBOM MERGE hierarchical: files=${mergeFiles.size()}, parallel_merge=${parallelMergeEnabled}, output=${mergedPath}")

    // Общий graph строит cyclonedx-cli --hierarchical.
    mergeHierarchicalSbomFiles(mergeFiles, mergedPath, cyclonedxCliPath, specVersion, sbomTemplatePath)

    // После CLI убираем только технические root-дубли и self-dependency.
    finalizeHierarchicalSbom(mergedPath, sbomTemplatePath)
}

// Родительские и корневые сканы исключают запланированные дочерние директории, чтобы не сканировать один source дважды.
def getEntryPlannedExcludeDirs(def entry, def plannedDirs) {
    normalizeList(plannedDirs).findAll { plannedDir ->
        plannedDir != entry.projectDir && plannedDir.startsWith("${entry.projectDir}/")
    }.unique()
}

// Помечает дублирующиеся URL кеша до параллельного выполнения, чтобы только одна ветка пыталась делать PUT.
void markDuplicateCacheSaveEntries(def entries) {
    def seenUrls = [] as Set
    normalizeList(entries).findAll { it.cacheKey && it.cacheContext }.each { entry ->
        def url = getCacheObjectUrl(entry.cacheContext, entry)
        if (url && seenUrls.contains(url)) {
            entry.skipCacheSave = true
        }
        if (url) {
            seenUrls << url
        }
    }
}

// Независимая единица работы: восстановить кеш, при необходимости просканировать, затем сохранить свежий непустой результат.
void runScanEntryWorkflow(def entry, def cdxgenPath, def excludeDirs = []) {
    if (entry.cacheKey && entry.cacheContext) {
        restoreFromCache(entry.cacheContext, entry)
    }

    if (entry.cacheStatus == "hit") {
        entry.cacheSaveStatus = "skip"
        echo("SBOM cache SAVE SKIP: backend=${entry.cacheContext.backend}, ${getEntryLogLabel(entry)}, reason=already restored from cache")
        return
    }

    if (!fileExists(entry.sbomPath)) {
        runScan(entry, cdxgenPath, excludeDirs)
    } else {
        echo("SBOM scan HOST SKIP: ${getEntryLogLabel(entry)}, reason=sbom already exists")
    }

    if (entry.cacheKey && entry.cacheContext) {
        if (entry.skipCacheSave) {
            entry.cacheSaveStatus = "skip"
            echo("SBOM cache SAVE SKIP: backend=${entry.cacheContext.backend}, ${getEntryLogLabel(entry)}, reason=duplicate cache key in run")
            return
        }
        saveToCache(entry.cacheContext, entry)
    }
}

// Главная точка входа pipeline: найти проекты, выполнить сценарии записей, объединить SBOM и прикрепить артефакт.
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
            def parallelEnabled = isParallelEnabled(extension)
            def parallelMergeEnabled = isParallelMergeEnabled(extension)

            if (useNewVersion) {
                // Новые версии cdxgen умеют исключать репозитории со своим SBOM и не должны сканировать workspace .m2.
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

            // Поиск проектов также создаёт сгенерированные корни анализа внутри каждого активного проекта.
            def excludedDirs = excludedSbomMap.keySet() as List
            def projectDirs = getProjectDirs(globals, useNewVersion, sourceDirs, excludedDirs)
            def cacheContexts = [:]
            def projectEntries = projectDirs.findAll { fileExists(it) }.collectMany { projectDir ->
                def scanConfig = getScanConfig(globals, sourceOverrides, globalCacheConfigs, cdxgenArgs, baseEnvMap, projectDir)
                createScanEntries(globals, projectDir, defaultSbomName, scanConfig)
            }

            // Ключи кеша готовятся до параллельного выполнения, чтобы можно было найти дублирующиеся URL.
            projectEntries.each { entry ->
                if (entry.projectDir == globals.DIR_SRC) {
                    entry.cacheConfig = null
                }
                if (prepareCacheKey(entry, cdxgenVersion, mavenSettingsId)) {
                    def contextKey = cacheConfigKey(entry.cacheConfig)
                    cacheContexts[contextKey] = cacheContexts[contextKey] ?: prepareCacheContext(globals, entry.cacheConfig)
                    entry.cacheContext = cacheContexts[contextKey]
                }
            }
            markDuplicateCacheSaveEntries(projectEntries)

            // Запланированные дочерние директории исключаются из родительских сканов, чтобы избежать повторного рекурсивного анализа.
            def plannedDirs = projectEntries.collect { it.projectDir }.unique()
            if (projectEntries) {
                ensureWorkspaceMavenCoveragePublisherSkipped()
            }

            // Каждая ветка теперь выполняет полный цикл: восстановление из Nexus -> скан cdxgen -> сохранение в Nexus.
            runWithCacheCredentials(cacheContexts.values()) {
                runEntriesPhase("ENTRY", projectEntries, parallelEnabled) { entry ->
                    runScanEntryWorkflow(entry, cdxgenPath, getEntryPlannedExcludeDirs(entry, plannedDirs))
                }
            }

            // В merge попадают только файлы, реально появившиеся после восстановления из кеша или нового скана.
            projectEntries.each { entry ->
                if (fileExists(entry.sbomPath)) scannedSbomPaths << entry.sbomPath
            }

            def allSboms = (sbomMergePaths.exists + scannedSbomPaths).unique()

            if (useNewVersion) {
                allSboms = (allSboms + excludedSbomMap.values()).unique()
            }

            // Итог намеренно короткий и стабильный, чтобы в логах Jenkins быстро видеть пользу кеша.
            def cacheableEntries = projectEntries.findAll { it.cacheKey }
            def cacheHits = cacheableEntries.count { it.cacheStatus == "hit" }
            def cacheMisses = cacheableEntries.count { it.cacheStatus == "miss" }
            def cacheUnavailable = cacheableEntries.count { it.cacheStatus == "unavailable" }
            def cacheSaves = cacheableEntries.count { it.cacheSaveStatus == "saved" }
            def cacheSaveSkips = cacheableEntries.count { it.cacheSaveStatus == "skip" }
            def cacheSaveFailed = cacheableEntries.count { it.cacheSaveStatus == "failed" }
            def cacheSkips = projectEntries.count { it.cacheStatus == "skip" }
            def hostScans = projectEntries.count { it.scanned }
            echo("SBOM summary: cache hits=${cacheHits}, misses=${cacheMisses}, unavailable=${cacheUnavailable}, " +
                "skips=${cacheSkips}, saves=${cacheSaves}, save skips=${cacheSaveSkips}, " +
                "save failed=${cacheSaveFailed}; Host scans=${hostScans}; merge files=${allSboms.size()}")

            def mergedPath = "${globals.DIR_SRC}/${defaultSbomName}"
            mergeSbomFiles(allSboms, mergedPath, specVersion, cyclonedxCliPath, globals, parallelMergeEnabled, sbomTemplatePath)

            echo("SBOM файлы успешно объединены: files=${allSboms.size()}, output=${mergedPath}")
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

// Простой семантический компаратор версий для проверок доступности возможностей cdxgen.
def versionAtLeast(def current, def required) {
    def result = (0..<required.size()).findResult { index ->
        int actual = index < current.size() ? current[index] : 0
        int expected = required[index]
        return actual == expected ? null : actual > expected
    }
    return result == null ? true : result
}

// Поведение cdxgen изменилось в 9.9.3; новые версии поддерживают используемый выше сценарий исключения SBOM.
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
