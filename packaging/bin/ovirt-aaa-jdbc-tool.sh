#!/bin/sh

PREFIX="${OVIRT_ENGINE_PREFIX:-/usr}"
ENGINE_USR="${ENGINE_USR:-${PREFIX}/share/ovirt-engine}"
ENGINE_ETC="${ENGINE_ETC:-/etc/ovirt-engine}"
JBOSS_HOME="${JBOSS_HOME:-${PREFIX}/share/ovirt-engine-wildfly}"
OVIRT_LOGGING_PROPERTIES="${OVIRT_LOGGING_PROPERTIES:-${ENGINE_ETC}/logging.properties}"

# engine-prolog.sh sources engine.conf.d entries as shell code. Do not invoke it
# when one of those entries is an authenticated binary envelope; Java will
# decrypt that configuration after the launcher has started safely.
encrypted_engine_config=false
for config in \
    "${ENGINE_ETC}/engine.conf.d/10-setup-database.conf" \
    "${ENGINE_ETC}/engine.conf.d/10-setup-dwh-database.conf"; do
    [ -r "${config}" ] || continue
    magic="$(LC_ALL=C dd if="${config}" bs=8 count=1 2>/dev/null)"
    if [ "${magic}" = "OVENC001" ] || [ "${magic}" = "OVVLT001" ]; then
        encrypted_engine_config=true
        break
    fi
done
if [ "${encrypted_engine_config}" = false ]; then
    prolog="${ENGINE_USR}/bin/engine-prolog.sh"
    if [ -r "${prolog}" ]; then
        . "${prolog}"
    fi
fi

if [ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME}/bin/java" ]; then
    JAVA="${JAVA_HOME}/bin/java"
else
    JAVA="$(command -v java)"
fi
if [ -z "${JAVA}" ] || [ ! -x "${JAVA}" ]; then
    echo "Unable to locate Java; set JAVA_HOME" >&2
    exit 1
fi
if [ ! -r "${JBOSS_HOME}/jboss-modules.jar" ]; then
    echo "Unable to locate ${JBOSS_HOME}/jboss-modules.jar; set JBOSS_HOME" >&2
    exit 1
fi

append_module_path() {
    [ -d "$1" ] || return 0
    if [ -n "${MODULE_PATH}" ]; then
        MODULE_PATH="${MODULE_PATH}:$1"
    else
        MODULE_PATH="$1"
    fi
}

MODULE_PATH="${ENGINE_JAVA_MODULEPATH:-}"
append_module_path "${ENGINE_USR}/modules/tools"
append_module_path "${PREFIX}/share/ovirt-engine-wildfly-overlay/modules"
append_module_path "${ENGINE_USR}/modules/common"
append_module_path "${PREFIX}/share/ovirt-engine-extension-aaa-jdbc/modules"
append_module_path "${PREFIX}/share/ovirt-engine-extension-aaa-misc/modules"
append_module_path "${JBOSS_HOME}/modules"
append_module_path "${JBOSS_HOME}/modules/system/layers/keycloak"
append_module_path "${JBOSS_HOME}/modules/system/layers/base"

"${JAVA}" \
    --add-modules java.se \
    -Djava.security.auth.login.config="${ENGINE_USR}/conf/jaas.conf" \
    -Djava.util.logging.config.file="${OVIRT_LOGGING_PROPERTIES}" \
    -Djboss.modules.write-indexes=false \
    -Dorg.ovirt.engine.aaa.jdbc.programName="${0}" \
    -Dorg.ovirt.engine.aaa.jdbc.engineEtc="${ENGINE_ETC}" \
    -jar "${JBOSS_HOME}/jboss-modules.jar" \
    -mp "${MODULE_PATH}" \
    -dependencies org.ovirt.engine.extension.aaa.jdbc \
    -class org.ovirt.engine.extension.aaa.jdbc.binding.cli.Cli \
    "$@"

rc=$?
if [ "${rc}" -eq 0 ]; then
    result="successfully."
else
    result="with failure."
fi
params="$(printf '%s\n' "$*" | sed 's/password=pass:[^[:space:]]*/password=pass:***/g')"
logger "User '${USER:-unknown}' executed '$0 ${params}' ${result}"
exit "${rc}"
