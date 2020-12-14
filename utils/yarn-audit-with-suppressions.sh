#!/bin/bash
function usage() {
  echo 'yarn-audit-with-suppress.sh -o outdir'
}

suppressions="audit/suppressions"
errors=""
while getopts ':s:' opt; do
  case ${opt} in
    s)  suppressions="${OPTARG}"
        ;;
    \?) echo "Invalid option: ${OPTARG}" 1>&2
        usage 1>&2
        errors=1
        ;;
    :)  echo "Invalid option: ${OPTARG}" 1>&2
        usage 1>&2
        errors=1
        ;;
  esac
done

if [ -n "$errors" ]; then
  exit 1
fi

if [ -f "${suppressions}" ]; then
  yarn audit --json | jq -c 'select(.type == "auditAdvisory").data.advisory | {id, title, module_name, vulnerable_versions, patched_versions, severity}' | (new=""; while read advisory ; do
    id=$(echo "${advisory}" | jq '.id')
    if ! grep -q "^${id}$" "${suppressions}"; then
      echo "New advisory ${id}:"
      echo "${advisory}" | jq .
      new=1
    fi
  done
  if [ -n "${new}" ]; then
    exit 1
  fi
  )
else
  yarn audit
fi
