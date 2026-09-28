// `sagebox completion zsh|bash`가 출력하는 셸 자동완성 스크립트. 비밀·프로필 이름은 금고를 열어야 해서 넣지 않는다.
use crate::vault::Result;

const ZSH: &str = r#"#compdef sagebox

_sagebox() {
  local -a cmds
  cmds=(
    'ns:show the current and available namespaces'
    'trust:trust this project for its .sagebox namespace'
    'untrust:remove a trusted project'
    'init:create a new vault'
    'set:add or replace a secret'
    'rm:delete a secret'
    'list:show secret names, expiry dates and profiles'
    'audit:verify the audit log'
    'import:move plaintext secrets out of an MCP config'
    'import-env:move plaintext secrets out of .envrc or .env'
    'mcp:add an MCP server or run the sagebox MCP server'
    'profile:remove a profile'
    'unlock:unlock the session'
    'lock:lock the session'
    'status:show whether the session is unlocked'
    'touchid:manage the Touch ID slot'
    'exec:run a profile with its secrets'
    'run:run a command with the project env'
    'zsh:print the zsh cd hook'
    'bash:print the bash cd hook'
    'completion:print a shell completion script'
  )
  if [[ $words[2] == --ns ]]; then
    if (( CURRENT == 3 )); then
      compadd -- ${(s:, :)${${(M)${(f)"$(sagebox ns 2>/dev/null)"}:#available: *}#available: }}
      return
    fi
    words=($words[1] $words[4,-1])
    (( CURRENT -= 2 ))
  fi
  if (( CURRENT == 2 )); then
    _describe -t commands 'sagebox command' cmds
    compadd -- --ns
    return
  fi
  # `--` 뒤는 실행할 명령이라 일반 자동완성에 맡긴다.
  local i=${words[(i)--]}
  if (( i < CURRENT )) && [[ $words[2] == (run|mcp) ]]; then
    shift $i words
    (( CURRENT -= i ))
    _normal
    return
  fi
  case $words[2] in
    import|import-env)
      if (( CURRENT == 3 )); then _files; else compadd -- --keep --apply; fi ;;
    set) (( CURRENT == 4 )) && compadd -- --expires ;;
    audit) compadd verify ;;
    touchid) compadd enable disable status ;;
    profile) (( CURRENT == 3 )) && compadd rm ;;
    mcp)
      if (( CURRENT == 3 )); then compadd add serve
      elif [[ $words[CURRENT-1] == --scope ]]; then compadd local user project
      elif [[ $words[3] == add ]] && (( CURRENT > 4 )); then compadd -- --env --scope --
      fi ;;
    completion) compadd zsh bash ;;
    untrust) _directories ;;
    run) (( CURRENT == 3 )) && compadd -- -- ;;
  esac
}

_sagebox "$@"
"#;

const BASH: &str = r#"_sagebox() {
  local cur=${COMP_WORDS[COMP_CWORD]} i=1 j w
  if [[ ${COMP_WORDS[1]} == --ns ]]; then
    if (( COMP_CWORD == 2 )); then
      w=$(sagebox ns 2>/dev/null | sed -n 's/^available: //p' | tr -d ,)
      COMPREPLY=($(compgen -W "$w" -- "$cur"))
      return
    fi
    i=3
  fi
  local cmd=${COMP_WORDS[i]} pos=$((COMP_CWORD - i))
  # `--` 뒤는 실행할 명령이라 명령·파일 이름으로 채운다.
  for ((j = i; j < COMP_CWORD; j++)); do
    if [[ ${COMP_WORDS[j]} == -- ]]; then
      COMPREPLY=($(compgen -c -f -- "$cur"))
      return
    fi
  done
  if (( pos == 0 )); then
    COMPREPLY=($(compgen -W "--ns ns trust untrust init set rm list audit import import-env mcp profile unlock lock status touchid exec run zsh bash completion" -- "$cur"))
    return
  fi
  case $cmd in
    import|import-env)
      if (( pos == 1 )); then COMPREPLY=($(compgen -f -- "$cur")); return; fi
      w="--keep --apply" ;;
    set) (( pos == 2 )) && w=--expires ;;
    audit) w=verify ;;
    touchid) w="enable disable status" ;;
    profile) (( pos == 1 )) && w=rm ;;
    mcp)
      if (( pos == 1 )); then w="add serve"
      elif [[ ${COMP_WORDS[COMP_CWORD-1]} == --scope ]]; then w="local user project"
      elif [[ ${COMP_WORDS[i+1]} == add ]] && (( pos > 2 )); then w="--env --scope --"
      fi ;;
    completion) w="zsh bash" ;;
    untrust) COMPREPLY=($(compgen -d -- "$cur")); return ;;
    run) (( pos == 1 )) && w=-- ;;
  esac
  COMPREPLY=($(compgen -W "$w" -- "$cur"))
}
complete -F _sagebox sagebox
"#;

pub fn script(shell: &str) -> Result<&'static str> {
    match shell {
        "zsh" => Ok(ZSH),
        "bash" => Ok(BASH),
        _ => Err(format!("unsupported shell {shell} (use zsh or bash)").into()),
    }
}
