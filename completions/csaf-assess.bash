# Generated from invoke_assessment.build_parser(). Refresh with:
# csaf-assess --completion bash > completions/csaf-assess.bash
_csaf_assess() {
  COMPREPLY=( $(compgen -W "-h --help --cloud --profile --regions --catalog --baseline --engagement --engagement-key-file --previous-findings --aws-profile --subscription --project --kube-context --kubeconfig --max-workers --output-dir --export --attest-key-file --log-level --explain --check-only --preflight --plan --tutorial --cleanup-tutorial --no-color --color --completion --output-format --self-check --version" -- "${COMP_WORDS[COMP_CWORD]}") )
}
complete -F _csaf_assess csaf-assess
