# Generated from invoke_assessment.build_parser().
Register-ArgumentCompleter -CommandName csaf-assess -ScriptBlock {
  param($wordToComplete)
  @('-h','--help','--cloud','--profile','--regions','--catalog','--baseline','--engagement','--engagement-key-file','--previous-findings','--aws-profile','--subscription','--project','--kube-context','--kubeconfig','--max-workers','--output-dir','--export','--attest-key-file','--log-level','--explain','--check-only','--preflight','--plan','--tutorial','--cleanup-tutorial','--no-color','--color','--completion','--output-format','--self-check','--version') |
    Where-Object { $_ -like "$wordToComplete*" } |
    ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterName', $_) }
}
