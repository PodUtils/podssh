# podssh serve --shell-integration (T-120): zsh starts with ZDOTDIR here, and
# reads this file first. The lines above gave ZDOTDIR back its value of the
# session, so zsh reads each later file of the user's where it would have.
# This one reads the user's .zshenv, then adds the marks of OSC 133 (prompt,
# command, output, status) and OSC 7 (the working directory) by hooks. It
# writes no file of the user's, and serve removes it when the session ends.
if [[ -r "${ZDOTDIR:-$HOME}/.zshenv" ]]; then
  builtin source "${ZDOTDIR:-$HOME}/.zshenv"
fi

if [[ -o interactive ]]; then
  # The path as a URL: each byte but the unreserved ones in %XX.
  __podssh_url() {
    emulate -L zsh
    local LC_ALL=C s=$1 out= c
    local -i i
    for ((i = 1; i <= ${#s}; i++)); do
      c=${s[i]}
      case $c in
        ([A-Za-z0-9/._~-]) out+=$c ;;
        (*) out+=$(builtin printf '%%%02X' "'$c") ;;
      esac
    done
    builtin printf '%s' "$out"
  }

  # Before each prompt: the end of the last command with its status, the
  # directory, the start of the prompt, and the end of the prompt in PS1.
  __podssh_precmd() {
    local podssh_rc=$?
    if (( ${+__podssh_ran} )); then
      builtin printf '\033]133;D;%s\007' "$podssh_rc"
      unset __podssh_ran
    fi
    builtin printf '\033]7;file://%s%s\007' "$HOST" "$(__podssh_url "$PWD")"
    builtin printf '\033]133;A\007'
    [[ $PS1 == *'133;B'* ]] || PS1+=$'%{\033]133;B\007%}'
  }

  # Before a command runs: the start of its output.
  __podssh_preexec() {
    __podssh_ran=1
    builtin printf '\033]133;C\007'
  }

  autoload -Uz add-zsh-hook && {
    add-zsh-hook precmd __podssh_precmd
    add-zsh-hook preexec __podssh_preexec
  }
fi
