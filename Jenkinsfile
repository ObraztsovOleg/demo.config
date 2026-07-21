def onDistrib(app, currentDistr) {
    def venvDir = "${pwd()}/python_sbom_sample/.venv"

    sh "python3 -m venv ${venvDir}"
    sh "${venvDir}/bin/python -m pip install -r python_sbom_sample/requirements.txt"

    env.VIRTUAL_ENV = venvDir
    env.PATH = "${venvDir}/bin:${env.PATH}"
    sh "python -m pip freeze"
}

return this
