# podssh serve --shell-integration (T-120): bash reads this file in place of
# ~/.bashrc (--rcfile, -i). It reads the files of a login, in the order of a
# login bash, then adds the marks of OSC 133 (prompt, command, output, status)
# and OSC 7 (the working directory). It writes no file of the user's, and serve
# removes it when the session ends.
if [ -r /etc/profile ]; then . /etc/profile; fi
if [ -r ~/.bash_profile ]; then . ~/.bash_profile
elif [ -r ~/.bash_login ]; then . ~/.bash_login
elif [ -r ~/.profile ]; then . ~/.profile
fi

# The path as a URL: each byte but the unreserved ones in %XX.
__podssh_url() {
  local LC_ALL=C s=$1 out= c i
  for ((i = 0; i < ${#s}; i++)); do
    c=${s:i:1}
    case $c in
      [A-Za-z0-9/._~-]) out+=$c ;;
      *) printf -v c '%%%02X' "'$c"; out+=$c ;;
    esac
  done
  printf '%s' "$out"
}

# Before each prompt: the end of the last command with its status, the
# directory, the start of the prompt, and the end of the prompt in PS1.
__podssh_prompt() {
  local podssh_rc=$?
  if [ -n "${__podssh_ran-}" ]; then printf '\033]133;D;%s\007' "$podssh_rc"; fi
  __podssh_ran=
  printf '\033]7;file://%s%s\007' "${HOSTNAME-}" "$(__podssh_url "$PWD")"
  printf '\033]133;A\007'
  case $PS1 in
    *'133;B'*) ;;
    *) PS1=$PS1'\[\033]133;B\007\]' ;;
  esac
  return "$podssh_rc"
}

# Before the first command of a line: the start of its output. Armed by the
# last step of PROMPT_COMMAND, so that the prompt's own commands mark nothing.
__podssh_preexec() {
  if [ -n "${__podssh_armed-}" ]; then
    __podssh_armed=
    __podssh_ran=1
    printf '\033]133;C\007'
  fi
}

PROMPT_COMMAND="__podssh_prompt${PROMPT_COMMAND:+;$PROMPT_COMMAND};__podssh_armed=1"
# A DEBUG trap of the user's own stays: the output then has no start mark.
if [ -z "$(trap -p DEBUG)" ]; then trap '__podssh_preexec' DEBUG; fi
